// Package agent — хост: регистрация на сервере, проверка пароля, захват экрана ffmpeg → H.264 → WebRTC,
// приём ввода по каналу данных "input".
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"anypc/hub"
	"anypc/pake"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/pion/interceptor"
	"github.com/pion/interceptor/pkg/cc"
	"github.com/pion/interceptor/pkg/gcc"
	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/pion/webrtc/v4/pkg/media/h264reader"

	"filippo.io/cpace"
)

type Agent struct {
	Server string // wss://…/ws; несколько хабов — через запятую (хост в сети на каждом)
	ID     string // 9 цифр
	// Secret — учётная запись по имени (UserKey; "" — по умолчанию, REQ-S-20): соль, KDF(пароль, соль), права
	// «просмотр»; пустой secret — нет такой записи или пароль не задан.
	Secret  func(user string) (salt, secret []byte, view bool)
	Key     ed25519.PrivateKey // ключ хоста: за ним закреплён ID (REQ-F-01), им хост подтверждает себя клиенту
	FF      []string           // аргументы ffmpeg, см. FFArgs
	FPS     int
	Stderr  io.Writer                                           // вывод ffmpeg; nil — os.Stderr
	OnState func(online bool, session string)                   // session "" — сессии нет
	FileDir string                                              // куда принимать файлы; "" — DownloadsDir()
	Capture func(ctx context.Context, c Cap) (*exec.Cmd, error) // захват по Cap (H.264 Annex-B или Y4M в stdout); nil — FFmpeg + FF
	Bitrate int                                                 // кбит/с — потолок адаптивного битрейта (REQ-N-03); 0 — постоянный
	Confirm func(cid, peer string) Answer                       // REQ-F-03: спросить человека на хосте после верного пароля; nil — не спрашивать (unattended)
	Trusted func(pub []byte, user string) bool                  // У3: ключ клиента закреплён за записью user (вход с ним был; AnyUser — за любой); nil — без доверенных
	Trust   func(pub []byte, user string)                       // закрепить ключ клиента за записью после входа по паролю
	Audio   bool                                                // окно хоста умеет звук (PLAN.md): клиент увидит кнопку микрофона
	Locked  func() bool                                         // экран заблокирован — захват не запускать (macOS, F7); nil — не проверять
	// Второй фактор входа без подтверждения (PLAN.md «TOTP»). Unattended — окно «Разрешить» выключено в настройках
	// (Confirm == nil — тоже без подтверждения). OTP: set — секрет TOTP задан, тогда после пароля нужен код; ok — код
	// верный (постоянное время и защита от повтора — у владельца секрета). Без секрета вход без подтверждения не
	// работает: спрашивается Confirm («Разрешить»), а без Confirm — отказ. OTP == nil — TOTP нет вовсе (как раньше).
	Unattended func() bool
	ViewOnly   func() bool                            // «Только показ экрана» на хосте: каждая сессия — только просмотр (REQ-F-20); nil — нет
	OTP        func(user, code string) (set, ok bool) // у каждой записи свой секрет TOTP
	// CodeUsed — одноразовый код израсходован (PLAN.md «одноразовый код»): кончилась сессия, прошедшая пароль
	// (вошедшая или отклонённая на хосте), или вход записью по умолчанию заперт перебором. Зовётся без a.mu, в своей
	// горутине; nil — кода нет.
	CodeUsed func()

	mu        sync.Mutex
	ice       []webrtc.ICEServer
	rtt       map[string]int       // мс от хоста до каждого TURN (замер по hello, не чаще measureEvery)
	rttAt     map[string]time.Time // когда мерили этот набор TURN
	sess      *session             // сессия с верным паролем (одна); до него — в pend
	pend      map[*session]bool    // незавершённые входы: не больше maxPending, «занят» — только при sess
	starting  int                  // занятые места pend, пока newSession шлёт offer (без a.mu)
	fails     int                  // неудачи паролей и кодов по хосту (все имена, REQ-S-22): с hostLockAt — блокировка входа всем, кроме закреплённых ключей
	lockUntil time.Time
	failAt    time.Time            // последняя неудача по хосту (hostStep)
	names     map[string]*nameLock // неудачи по имени записи (REQ-S-22): и для несуществующих имён — иначе блокировка выдала бы, есть ли имя
	otpFails  int                  // неверные коды TOTP по хосту (все записи): с hostLockAt шаг кода заперт всем, кроме закреплённых ключей;
	otpLock   time.Time            // у каждой записи ещё своя лестница кодов (nameLock.otpFails, как одна лестница v0.1.19)
	otpAt     time.Time            // последний неверный код по хосту (hostStep)
	online    map[string]bool      // хабы, на которых хост зарегистрирован
}

type session struct {
	cid     string
	user    string          // учётная запись входа (UserKey; "" — по умолчанию), REQ-F-24
	salt    []byte          // соль записи при входе (под mu): сменилась — пароль сменили или запись удалили (DropRevoked)
	conn    *websocket.Conn // хаб, через который пришёл клиент
	pc      *webrtc.PeerConnection
	keys    held
	copied  atomic.Bool // клиент нажал Ctrl+C/X — проверить буфер (clipOnCopy)
	clip    clipSync
	authed  atomic.Bool // до успешного CPace ни видео, ни ввод, ни буфер обмена, ни файлы не работают
	audio   audioState
	view    atomic.Bool // REQ-F-20 «только просмотр»: от клиента — ни ввода, ни буфера, ни файлов; буфер хоста ему не уходит
	picking atomic.Bool // открыто окно выбора файла
	asking  atomic.Bool // на хосте открыто окно «Разрешить / Отклонить» или ждём код TOTP
	gone    atomic.Bool // сессия освобождена (release) — в pend не возвращать
	ctl     *webrtc.DataChannel
	peer    string // адрес клиента по выбранной паре ICE — для окна подтверждения
	ice     iceCap // потолок удалённых ICE-кандидатов (F5, icecap.go)

	mu        sync.Mutex
	closeInd  func() // закрыть плашку сессии
	mons      []Monitor
	mon       int                   // выбранный монитор (индекс в mons)
	capCancel context.CancelFunc    // остановить текущий процесс захвата
	capStart  time.Time             // старт текущего захвата — PLI раньше pliHold после него не перезапускает
	vp9       bool                  // кодек сессии выбран при её создании (connect.vp9) и не меняется до конца
	pace      *pacer                // темп отправки видео (pace.go): битрейт — из rate
	inproc    atomic.Bool           // кодер в процессе работает: битрейт, к/с и ключевой кадр меняются без перезапуска захвата
	keyReq    atomic.Bool           // кодеру в процессе: следующий кадр — ключевой (PLI)
	switched  atomic.Bool           // захват остановлен ради смены монитора/битрейта — перезапуск без паузы
	rate      rate                  // адаптивный битрейт; max == 0 — выключен
	bwe       cc.BandwidthEstimator // оценка полосы GCC по TWCC клиента; nil — без неё
	denied    atomic.Bool           // захват отклонён человеком у хоста (ErrCaptureDenied) — сессия закрывается
	state     string                // состояние захвата для клиента (F7): "" — ещё не сообщали, "locked", "nocapture", "ok"
	stateAt   time.Time             // когда state последний раз уходил клиенту (повтор — repeatState)
	twcc      atomic.Bool           // от клиента пришёл первый отчёт TWCC (в журнал — один раз)
}

// monitor — выбранный монитор для пересчёта координат мыши (nil — мониторов не знаем).
func (s *session) monitor() *Monitor {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mon < len(s.mons) {
		m := s.mons[s.mon]
		return &m
	}
	return nil
}

// selectMonitor переключает захват на монитор i (REQ-F-09): текущий захват останавливается,
// цикл stream сразу запускает новый — клиент получает новый ключевой кадр.
func (s *session) selectMonitor(i int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i < 0 || i >= len(s.mons) || i == s.mon {
		return false
	}
	s.mon = i
	s.switched.Store(true)
	if s.capCancel != nil {
		s.capCancel()
	}
	return true
}

// authMsg — канал "auth" (REQ-S-02): хост → {"t":"a",salt,msg}; клиент → {"t":"b",msg,conf};
// хост → {"t":"ok",conf} | {"t":"fail"}. []byte — base64 в JSON.
// Вход без подтверждения с TOTP: после верного пароля хост → {"t":"otp",conf,pub,sig} (доказательства — как в "ok"),
// клиент → {"t":"otp","code":"123456"};
// верный код → "ok", неверный → снова {"t":"otp"} или "locked" (счётчик перебора — общий с паролем), не ввели за
// otpWait90 → "denied".
// Учётные записи (REQ-S-20, только добавления): в первом "a" хоста — users:true (хост понимает имена; соль и msg — записи
// по умолчанию, старый клиент входит ею). Клиент с именем вместо "b" шлёт {"t":"a","user":"имя"} (одно на сессию),
// хост — новое {"t":"a",salt,msg,"user":"имя"}: соль записи или, если имени нет, поддельная HMAC-SHA256(ключ хоста,
// имя)[:16] (REQ-S-21), дальше "b" как обычно. Обмен CPace у клиента по-прежнему один — на "a" со своим именем.
type authMsg struct {
	T     string `json:"t"`
	User  string `json:"user,omitempty"`  // в "a": имя учётной записи (от клиента — запрос, от хоста — ответ на него)
	Users bool   `json:"users,omitempty"` // в первом "a" хоста: хост понимает имена записей
	Salt  []byte `json:"salt,omitempty"`
	Msg   []byte `json:"msg,omitempty"`
	Conf  []byte `json:"conf,omitempty"`
	Pub   []byte `json:"pub,omitempty"` // в "ok": ключ хоста и подпись над DTLS-отпечатками (REQ-S-05)
	Sig   []byte `json:"sig,omitempty"`
	View  bool   `json:"view,omitempty"`  // в "ok": сессия «только просмотр» (REQ-F-20)
	Audio bool   `json:"audio,omitempty"` // в "ok": хост умеет звук (окно хоста ответит на предложение)
	CPub  []byte `json:"cpub,omitempty"`  // в "b": ключ клиента и его подпись над DTLS-отпечатками (У3)
	CSig  []byte `json:"csig,omitempty"`
	Code  string `json:"code,omitempty"`  // в "otp" от клиента: код TOTP
	NoOTP bool   `json:"nootp,omitempty"` // в "ask": вход без подтверждения выключен, пока на хосте не настроят TOTP
}

// ctlMsg — канал "ctl": {"t":"clip","text":"…"} — буфер обмена в обе стороны (REQ-F-11);
// {"t":"pick"} от клиента — открыть на хосте окно выбора файла и отправить выбранный (REQ-F-12);
// хост → {"t":"monitors","list":[…],"cur":i}, клиент → {"t":"monitor","i":N} — выбор монитора (REQ-F-09).
// Клиент → {"t":"quality","p":"text"|"video"} — профиль картинки (Cap.Video);
// хост → {"t":"cur","x":…,"y":…,"c":"text"} — курсор хоста: точка 0..65535 в текущем мониторе и форма именем CSS,
// {"t":"cur","c":"none"} — скрыт или вне монитора (cursor.go).
type ctlMsg struct {
	T    string    `json:"t"`
	Text string    `json:"text,omitempty"`
	List []Monitor `json:"list,omitempty"`
	Cur  int       `json:"cur"`
	I    int       `json:"i"`
	P    string    `json:"p,omitempty"`
	X    int       `json:"x,omitempty"`
	Y    int       `json:"y,omitempty"`
	C    string    `json:"c,omitempty"`
	SDP  string    `json:"sdp,omitempty"` // "audio": предложение клиента / ответ окна хоста (PLAN.md, звук)
	Err  string    `json:"err,omitempty"` // "audio": "closed" — окно хоста не ответило
	S    string    `json:"s,omitempty"`   // "state": "locked" | "nocapture" | "ok" (F7; старый клиент неизвестный t пропускает)
}

// Cap — параметры захвата: монитор, потолок битрейта (кбит/с), кадров/с; Video — профиль «видео» (частота кадров
// важнее чёткости: к/с не снижается, на канале < 2 Мбит/с картинка ужимается до 720p); Cursor — рисовать курсор
// в кадр (false — хост шлёт его отдельно по ctl, см. cursor.go: кадр при движении одной мыши остаётся статичным).
type Cap struct {
	Mon, Kbps, FPS int
	Video, Cursor  bool
	VP9            bool // кодер VP9 в процессе: ffmpeg отдаёт Y4M, enc игнорируется (см. FFArgs)
}

// c.VP9 — ffmpeg не кодирует: кадры Y4M (yuv420p, чётные размеры) в stdout для кодера в процессе (vp9.go); enc тогда
// не важен. Без c.VP9 enc "vp9" (настройка при сборке без кодера) → libx264.
func FFArgs(src, enc string, c Cap) []string {
	switch {
	case c.VP9:
		enc = "vp9"
	case enc == "vp9":
		enc = "libx264"
	}
	fps, br, cur := c.FPS, strconv.Itoa(c.Kbps)+"k", "0"
	if c.Cursor {
		cur = "1"
	}
	a := []string{"-hide_banner", "-loglevel", "warning"}
	var vf []string
	if src == "test" {
		a = append(a, "-re", "-f", "lavfi", "-i", fmt.Sprintf("testsrc2=size=1280x720:rate=%d", fps))
	} else if in, ok := strings.CutPrefix(src, "x11:"); ok { // Linux X11: "x11::0" или "x11:WxH@:0+X,Y"
		a = append(a, "-f", "x11grab", "-framerate", strconv.Itoa(fps), "-draw_mouse", cur)
		if size, disp, ok := strings.Cut(in, "@"); ok {
			a = append(a, "-video_size", size)
			in = disp
		}
		a = append(a, "-i", in)
	} else if n, ok := strings.CutPrefix(src, "avf:"); ok { // macOS: экран N по avfoundation
		a = append(a, "-f", "avfoundation", "-capture_cursor", cur, "-framerate", strconv.Itoa(fps), "-pixel_format", "uyvy422", "-i", "Capture screen "+n+":none")
		vf = append(vf, fmt.Sprintf("fps=%d", fps)) // экран avfoundation -framerate не слушает («Configuration … failed»): без фильтра — тысячи кадров/с и серый экран у клиента
	} else { // Windows 8+, ffmpeg ≥ 6.0: "desktop" или "desktop:N" (N — выход DXGI)
		out := 0
		if n, ok := strings.CutPrefix(src, "desktop:"); ok {
			out, _ = strconv.Atoi(n)
		}
		a = append(a, "-f", "lavfi", "-i", fmt.Sprintf("ddagrab=output_idx=%d:framerate=%d:draw_mouse=%s", out, fps, cur))
		vf = append(vf, "hwdownload", "format=bgra")
	}
	if c.Video && c.Kbps < 2000 { // профиль «скорость» на узком канале: 720p (не растягивать меньшие экраны), ширина чётная
		vf = append(vf, "scale=-2:'min(720,ih)'")
	} else if enc == "vp9" {
		vf = append(vf, "scale=trunc(iw/2)*2:trunc(ih/2)*2") // Y4M 4:2:0 — чётные размеры
	}
	if len(vf) > 0 {
		a = append(a, "-vf", strings.Join(vf, ","))
	}
	if enc == "vp9" {
		return append(a, "-pix_fmt", "yuv420p", "-f", "yuv4mpegpipe", "-")
	}
	// Статика не деградирует вместе с каналом (LOGBOOK 2026-11-09: текст 1080p на 500 кбит/с):
	// libx264 — CRF 20 с потолком VBV (битрейт из rate — только -maxrate/-bufsize) и без периодических I-кадров:
	// I-кадр раз в секунду упирался в VBV одной секунды битрейта и каждый раз перерисовывал неизменную картинку
	// (PSNR пилой 23–34 дБ); теперь неизменные блоки дорисовываются P-кадрами до CRF (28 → 48 дБ за 6 с),
	// статика стоит 11–66 байт/кадр, при движении VBV держит потолок (4175 кбит/с при 4M). intra-refresh отвергнут:
	// каждая новая волна перекодирует хорошую картинку при QP 39–44 (45 → 30 дБ). Смена сцены — IDR по scenecut.
	// Потеря кадра лечится PLI (onRTCP) → перезапуск захвата. Аппаратные кодеры — как раньше: ABR, IDR раз в секунду.
	a = append(a, "-c:v", enc, "-maxrate", br, "-bufsize", br, "-bf", "0", "-pix_fmt", "yuv420p")
	if enc == "libx264" { // один слайс на кадр — длительность сэмпла ставится на слайс
		a = append(a, "-crf", "20", "-preset", "ultrafast", "-tune", "zerolatency", "-profile:v", "baseline", "-x264-params", "sliced-threads=0:keyint=infinite")
	} else {
		a = append(a, "-b:v", br, "-g", strconv.Itoa(fps))
	}
	return append(a, "-flush_packets", "1", "-f", "h264", "-")
}

// Run держит регистрацию на каждом хабе из Server, переподключаясь каждые 5 с до отмены ctx.
// Хост в сети на всех хабах сразу: клиент идёт через тот, что ответил ему первым, — синхронизировать хабы не нужно.
func (a *Agent) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, u := range strings.Split(a.Server, ",") {
		if u = strings.TrimSpace(u); u == "" {
			continue
		}
		wg.Go(func() {
			for ctx.Err() == nil {
				err := a.run(ctx, u)
				a.setOnline(u, false)
				log.Printf("сигнализация %s: %v — повтор через 5 с", u, err)
				select {
				case <-ctx.Done():
				case <-time.After(5 * time.Second):
				}
			}
		})
	}
	wg.Wait()
	a.Disconnect()
}

// Disconnect разрывает текущую сессию (кнопка «Разорвать» на хосте).
func (a *Agent) Disconnect() {
	a.mu.Lock()
	s := a.sess
	a.mu.Unlock()
	if s == nil {
		return
	}
	a.send(context.Background(), s.conn, "bye", s.cid, "host") // через хаб, по которому пришёл клиент
	s.pc.Close()
}

// DisconnectFull — хост включил «Только показ экрана»: вошедшую сессию с полным доступом разорвать (новая войдёт
// только просмотром); сессию «только просмотр» и ещё не вошедшую (шаг кода, окно «Разрешить») не трогать — accept
// сам выставит ей просмотр.
func (a *Agent) DisconnectFull() {
	a.mu.Lock()
	s := a.sess
	a.mu.Unlock()
	if s != nil && s.authed.Load() && !s.view.Load() {
		log.Printf("сессия %s: включён «Только показ экрана» — разорвана", s.cid)
		a.Disconnect()
	}
}

// DropRevoked — запись вошедшей сессии удалили, сменили ей пароль (новая соль) или сузили права до «просмотр»:
// сессия рвётся (REQ-S-20). Зовут после правки записей и из опроса настроек; ещё не вошедшую не трогать — она
// войдёт по тем данным, что были, и следующий вызов её разорвёт.
func (a *Agent) DropRevoked() {
	a.mu.Lock()
	s := a.sess
	a.mu.Unlock()
	if s == nil || !s.authed.Load() {
		return
	}
	if gone, view := a.revoked(s); !gone && (!view || s.view.Load()) {
		return
	}
	if a.byCID(s.cid) != s { // проверенная сессия уже кончилась — другую, успевшую войти, не трогать
		return
	}
	log.Printf("сессия %s: учётную запись удалили, сменили ей пароль или права — разорвана", s.label())
	a.send(context.Background(), s.conn, "bye", s.cid, "host")
	s.pc.Close()
}

// revoked — запись сессии s удалили или сменили ей пароль (соль не та, что при входе); view — права записи сейчас «просмотр».
func (a *Agent) revoked(s *session) (gone, view bool) {
	s.mu.Lock()
	user, was := s.user, s.salt
	s.mu.Unlock()
	salt, secret, view := a.Secret(user)
	return len(secret) == 0 || !bytes.Equal(salt, was), view
}

func (a *Agent) setOnline(hub string, on bool) {
	a.mu.Lock()
	if a.online == nil {
		a.online = map[string]bool{}
	}
	if on {
		a.online[hub] = true
	} else {
		delete(a.online, hub)
	}
	a.mu.Unlock()
	a.notify()
}

func (a *Agent) notify() {
	a.mu.Lock()
	on, cid := len(a.online) > 0, "" // в сети, если зарегистрирован хоть на одном хабе
	if a.sess != nil {
		cid = a.sess.label()
	}
	a.mu.Unlock()
	if a.OnState != nil {
		a.OnState(on, cid)
	}
}

func (a *Agent) send(ctx context.Context, c *websocket.Conn, typ, to string, v any) {
	d, _ := json.Marshal(v)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = wsjson.Write(ctx, c, hub.Msg{V: 1, Type: typ, To: to, Data: d})
}

const measureEvery = time.Minute

// measureDue — пора ли мерить набор TURN hs (и отметка, что замер начат).
func (a *Agent) measureDue(hs []string) bool {
	k := strings.Join(hs, " ")
	a.mu.Lock()
	defer a.mu.Unlock()
	if time.Since(a.rttAt[k]) < measureEvery {
		return false
	}
	if a.rttAt == nil {
		a.rttAt = map[string]time.Time{}
	}
	a.rttAt[k] = time.Now()
	return true
}

// readRTCP — до закрытия sender: RTCP нужно вычитывать, иначе не работают интерсепторы (NACK, TWCC → GCC);
// отчёты о потерях — битрейту.
func readRTCP(sender *webrtc.RTPSender, on func([]rtcp.Packet)) {
	b := make([]byte, 1500) // = receiveMTU pion
	for {
		n, _, err := sender.Read(b)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			return
		}
		if err != nil { // битый RTCP/TWCC от клиента: интерсепторы отдают ошибку разбора из Read — пропустить,
			time.Sleep(10 * time.Millisecond) // а не терять NACK и битрейт до конца сессии; пауза — от 100 % CPU на устойчивой ошибке
			continue
		}
		if pkts, err := rtcp.Unmarshal(b[:n]); err == nil {
			on(pkts)
		}
	}
}

// maxPending — незавершённых входов одновременно. Одна попытка занимала хост на 20 с: знающий ID
// повторял connect и держал владельца на «занят» без единой засчитанной неудачи (У3, У9).
const maxPending = 3

// release — освободить место сессии s (активной или незавершённой).
func (a *Agent) release(s *session) {
	s.gone.Store(true)
	a.mu.Lock()
	used := a.sess == s // прошла пароль (код): им уже вошли или его знает отклонённый — сменить
	if used {
		a.sess = nil
	}
	delete(a.pend, s)
	a.mu.Unlock()
	if used && a.CodeUsed != nil {
		go a.CodeUsed()
	}
}

// promote — пароль верный: s становится сессией хоста, если её не опередила другая.
func (a *Agent) promote(s *session) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess != nil && a.sess != s || s.gone.Load() {
		return false
	}
	a.sess = s
	delete(a.pend, s)
	return true
}

// byCID — сессия клиента cid (активная или незавершённая).
func (a *Agent) byCID(cid string) *session {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess != nil && a.sess.cid == cid {
		return a.sess
	}
	for s := range a.pend {
		if s.cid == cid {
			return s
		}
	}
	return nil
}

// proxy — прокси из окружения (HTTPS_PROXY…); переменная — для теста.
var proxy = http.ProxyFromEnvironment

// dial — сигнализация через прокси из окружения, а если он не отвечает — напрямую:
// забытый мёртвый HTTPS_PROXY не должен отрезать ПК от сети (так было на ПК владельца, 2026-11-06).
func dial(ctx context.Context, u string) (*websocket.Conn, error) {
	via := func(p func(*http.Request) (*url.URL, error)) *websocket.DialOptions {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = p
		return &websocket.DialOptions{HTTPClient: &http.Client{Transport: t}}
	}
	c, _, err := websocket.Dial(ctx, u, via(proxy))
	if op := (*net.OpError)(nil); errors.As(err, &op) && op.Op == "proxyconnect" {
		log.Printf("прокси из окружения не отвечает (%v) — подключаюсь напрямую", op.Err)
		c, _, err = websocket.Dial(ctx, u, via(nil))
	}
	return c, err
}

func (a *Agent) run(ctx context.Context, server string) error {
	pub := base64.RawURLEncoding.EncodeToString(a.Key.Public().(ed25519.PublicKey))
	c, err := dial(ctx, server+"?host="+a.ID+"&key="+pub)
	if err != nil {
		return err
	}
	defer c.CloseNow()
	c.SetReadLimit(64 << 10)
	kctx, stop := context.WithCancel(ctx)
	defer stop()
	go hub.Keepalive(kctx, c, hub.PingEvery) // обрыв по смене сети — переподключение за ~40 с, а не по TCP keepalive через минуты
	for {
		var m hub.Msg
		if err := wsjson.Read(ctx, c, &m); err != nil {
			return err
		}
		if m.From != "" && (m.Type == "challenge" || m.Type == "hello" || m.Type == "error") {
			continue // Д-4: служебное — только от самого хаба; пересланное хабом несёт From отправителя
		}
		switch m.Type {
		case "challenge": // REQ-F-01: доказать серверу владение ключом, за которым закреплён ID
			var nonce string
			json.Unmarshal(m.Data, &nonce)
			a.send(ctx, c, "register", "", map[string][]byte{"sig": ed25519.Sign(a.Key, pake.RegisterMsg(a.ID, nonce))})
		case "hello":
			var d struct{ ICE []webrtc.ICEServer }
			json.Unmarshal(m.Data, &d)
			a.mu.Lock()
			a.ice = d.ICE
			a.mu.Unlock()
			if hs := turnHosts(d.ICE); a.measureDue(hs) { // hello приходит перед каждым connect — без лимита спам connect плодит пробы
				go func() { r := measureTURN(hs); a.mu.Lock(); a.rtt = r; a.mu.Unlock() }()
			}
			log.Printf("зарегистрирован как %s, ICE-серверов: %d", a.ID, len(d.ICE))
			a.setOnline(server, true)
		case "error":
			log.Printf("сервер: %s", m.Data)
			switch string(m.Data) {
			case `"id_taken"`:
				return errors.New("ID занят: в сети другой экземпляр или ID закреплён за другим ключом")
			case `"limit"`:
				return errors.New("хаб: с этого адреса за час зарегистрировано слишком много новых ID — повтор позже")
			case `"bad_sig"`:
				return errors.New("сервер не принял подпись ключа хоста")
			}
		case "connect":
			a.onConnect(ctx, c, m)
		case "answer", "ice", "bye":
			s := a.byCID(m.From)
			if s == nil || s.conn != c { // ответ клиента — только по хабу его сессии
				continue
			}
			var err error
			switch m.Type {
			case "answer":
				var sd webrtc.SessionDescription
				if json.Unmarshal(m.Data, &sd) == nil {
					if !s.answerCands(sd.SDP) { // кандидаты в answer — в обход trickle; сверх потолка — отказ
						log.Printf("клиент %s: в answer кандидатов больше потолка — сессия отклонена", s.cid)
						a.send(ctx, c, "bye", s.cid, "host")
						a.release(s)
						s.pc.Close()
						continue
					}
					err = s.pc.SetRemoteDescription(sd)
				}
			case "ice":
				var ci webrtc.ICECandidateInit
				if json.Unmarshal(m.Data, &ci) == nil && s.ice.admit(s.cid, ci.Candidate, s.authed.Load()) {
					err = s.pc.AddICECandidate(ci)
				}
			case "bye":
				log.Printf("клиент %s завершил сессию", s.cid)
				a.release(s) // свободен сразу: колбэк pion о закрытии асинхронный, а следующий connect уже в пути
				s.pc.Close()
			}
			if err != nil {
				log.Printf("%s: %v", m.Type, err)
			}
		}
	}
}

// onConnect: блокировка перебора (REQ-S-04), занятость, наличие пароля. Сам пароль проверяется
// позже, по CPace внутри DTLS (REQ-S-02) — через сервер он не идёт.
// ponytail: блокировка общая на хост, не по клиенту — злоумышленник со знанием ID может мешать входу.
// clientID — ID клиента от хаба (hub.go: "c" + 12 цифр). Другое — подлог хаба: cid идёт в окно «Разрешить»
// и в плашку, и перевод строки в нём подделал бы строку «IP:».
var clientID = regexp.MustCompile(`^c[0-9]{12}$`)

func (a *Agent) onConnect(ctx context.Context, c *websocket.Conn, m hub.Msg) {
	if !clientID.MatchString(m.From) {
		log.Printf("connect с неверным ID клиента %q — пропущен", m.From)
		return
	}
	if _, secret, _ := a.Secret(""); len(secret) == 0 {
		a.send(ctx, c, "error", m.From, "nopass")
		return
	}
	var req connectReq
	json.Unmarshal(m.Data, &req)                                                                          // старый клиент шлёт {} — выбора нет, ICE получает все серверы
	trusted := a.Trusted != nil && len(req.CPub) == ed25519.PublicKeySize && a.Trusted(req.CPub, AnyUser) // имя ещё не известно
	extra := 0
	if trusted { // молчуны не займут места владельца; заявка без ключа отсеется в auth и освободит место
		extra = 2
	}
	// под a.mu — только занять место: offer уходит по сети до 5 с, а a.mu нужен циклам других хабов
	a.mu.Lock()
	var old *session // повторный connect того же клиента (переподключение): ответы шли бы не той сессии
	for p := range a.pend {
		if p.cid == m.From {
			old = p
			delete(a.pend, p)
		}
	}
	refuse := ""
	switch {
	case time.Now().Before(a.lockUntil) && !trusted: // доверенный клиент докажет ключ в auth (там же блокировка)
		refuse = "locked"
	case a.sess != nil || len(a.pend)+a.starting >= maxPending+extra:
		refuse = "busy"
	default:
		a.starting++
	}
	turn := pickTURN(req, a.rtt, turnHosts(a.ice))
	ice, rtt := onlyTURN(a.ice, turn), maps.Clone(a.rtt)
	a.mu.Unlock()
	if old != nil {
		old.gone.Store(true)
		old.pc.Close()
	}
	if refuse != "" {
		a.send(ctx, c, "error", m.From, refuse)
		return
	}
	if turn != "" {
		log.Printf("сессия %s: TURN %s (выбор клиента %q; клиент %v, хост %v мс)", m.From, turn, req.TURN, req.RTT, rtt)
	}
	s, err := a.newSession(ctx, c, m.From, ice, offerMsg{TURN: turn, RTT: rtt}, req.VP9 && VP9Built, req.View)
	a.mu.Lock()
	a.starting--
	var dup *session                  // два connect одного клиента, пока первый ещё слал offer: оставить последний
	if err == nil && !s.gone.Load() { // gone: сессия кончилась, пока шёл offer
		if a.pend == nil {
			a.pend = map[*session]bool{}
		}
		for p := range a.pend {
			if p.cid == s.cid {
				dup = p
				delete(a.pend, p)
			}
		}
		a.pend[s] = true
	}
	a.mu.Unlock()
	if dup != nil {
		dup.gone.Store(true)
		dup.pc.Close()
	}
	if err != nil {
		log.Printf("сессия: %v", err)
		a.send(ctx, c, "error", m.From, "internal")
	}
}

// authResult учитывает попытку входа для блокировки перебора.
func (a *Agent) authResult(cid, user string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.countAuth(cid, user, ok)
}

// nameLock — счётчики неудач одного имени записи (REQ-S-22): пароли и коды TOTP этой записи.
type nameLock struct {
	fails    int
	until    time.Time
	otpFails int // неверные коды этой записи: сбрасывает только верный код этой же записи
	otpUntil time.Time
	at       time.Time // последняя неудача (пароль или код)
}

// stale — строка имени затихла: nameForget после последней неудачи и после конца обеих блокировок — забыть. 5 попыток
// в сутки меньше, чем даёт установившаяся лестница (24 в сутки), — перебор не ослаблен.
func (n *nameLock) stale(now time.Time) bool {
	return now.After(n.at.Add(nameForget)) && now.After(n.until.Add(nameForget)) && now.After(n.otpUntil.Add(nameForget))
}

// nameForget — сутки тишины, после которых строка имени (и общая othersKey) забывается.
const nameForget = 24 * time.Hour

// hostLockAt — неудач по хосту (все имена) до общей блокировки: массовый перебор имён; одно имя запирается раньше —
// с 5-й (REQ-S-04), и перебор одного имени другие не запирает. maxNames — сколько имён помнить; имена с неудачами не
// вытесняются (иначе мусорные имена стирали бы счёт настоящего), новые сверх — в один общий счётчик othersKey.
// hostForget — общий счётчик забывается после стольких часов тишины после блокировки: успех записи его не
// сбрасывает (иначе свой вход раз в 19 неудач обнулял бы чужой перебор).
const hostLockAt, maxNames, hostForget = 20, 256, time.Hour

// othersKey — общий счётчик имён сверх maxNames (не совпадает ни с одним именем: UserKey и проверка в канале auth).
const othersKey = "\x01"

// nameOf — счётчики имени (под a.mu); create — завести, если нет. Сверх maxNames — общий othersKey.
func (a *Agent) nameOf(user string, create bool) *nameLock {
	now := time.Now()
	if n := a.names[user]; n != nil && !n.stale(now) {
		return n
	}
	delete(a.names, user)
	if len(a.names) >= maxNames { // таблица полна: сначала забыть затихшие (иначе одна атака навсегда сводит всех в othersKey)
		maps.DeleteFunc(a.names, func(_ string, l *nameLock) bool { return l.stale(now) })
	}
	if len(a.names) >= maxNames {
		user = othersKey
	}
	n := a.names[user]
	if n == nil && create {
		if a.names == nil {
			a.names = map[string]*nameLock{}
		}
		n = &nameLock{}
		a.names[user] = n
	}
	return n
}

// countAuth — то же под уже взятым a.mu: счётчик имени и общий по хосту. Успех сбрасывает только счёт своего имени.
func (a *Agent) countAuth(cid, user string, ok bool) {
	if ok {
		delete(a.names, user)
		return
	}
	n := a.nameOf(user, true)
	lockStep(&n.fails, &n.until, 5)
	n.at = time.Now()
	hostStep(&a.fails, &a.lockUntil, &a.failAt)
	log.Printf("неверный пароль или код от %s (запись %q: %d, всего %d)", cid, user, n.fails, a.fails)
	if now := time.Now(); a.CodeUsed != nil && (user == "" && now.Before(n.until) || now.Before(a.lockUntil)) {
		go a.CodeUsed() // перебор дошёл до блокировки: новый код, подобранное к старому не пригодится
	}
}

// hostStep — неудача в общий счётчик хоста; счёт забывается, если неудач не было hostForget после конца блокировки.
func hostStep(fails *int, until, at *time.Time) {
	now := time.Now()
	if now.After(at.Add(hostForget)) && now.After(until.Add(hostForget)) {
		*fails = 0
	}
	*at = now
	lockStep(fails, until, hostLockAt)
}

// pwLocked — вход паролем заперт: по хосту или по этому имени (под a.mu).
func (a *Agent) pwLocked(user string, now time.Time) bool {
	n := a.nameOf(user, false)
	return now.Before(a.lockUntil) || n != nil && now.Before(n.until)
}

// lockStep — ещё одна неудача: с at-й блокировка на 1 мин, дальше удвоение до 1 ч (REQ-S-04).
func lockStep(fails *int, until *time.Time, at int) {
	*fails++
	if *fails >= at {
		*until = time.Now().Add(min(time.Minute<<min(*fails-at, 6), time.Hour))
	}
}

// AnyUser — Trusted: ключ закреплён за любой записью (onConnect: имя придёт позже, в канале auth). Непечатаемое:
// имя от клиента с управляющими символами хост не принимает, и с AnyUser оно не совпадёт.
const AnyUser = "\x00"

// UserKey — имя записи для сравнения: без пробелов по краям и без регистра (настройки хранят его так же).
// Поддельная соль считается от него же: иначе «Ivan» и «ivan» у несуществующего имени дали бы разные соли, а у
// существующего — одну (REQ-S-21).
func UserKey(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// maxUserLen — длиннее имя от клиента не принимается (настройки допускают 32 символа).
const maxUserLen = 128

// userStart — соль и начало CPace для записи user (REQ-S-21): нет такой — поддельная соль HMAC-SHA256(ключ хоста,
// имя)[:16] и случайный секрет; работа одна и та же (HMAC и rand — всегда), по ответу и времени имя не узнать.
func (a *Agent) userStart(user, fpc, fph string) (salt, msg []byte, st *cpace.State, view bool, err error) {
	salt, secret, view := a.Secret(user)
	mac := hmac.New(sha256.New, a.Key)
	mac.Write([]byte(user))
	fake, rnd := mac.Sum(nil)[:16], make([]byte, 32)
	rand.Read(rnd)
	if len(secret) == 0 {
		salt, secret, view = fake, rnd, true
	}
	msg, st, err = pake.HostStart(secret, a.ID, fpc, fph)
	return salt, msg, st, view, err
}

// newAPI — WebRTC со стандартными интерсепторами (NACK, RTCP-отчёты, TWCC-ответы); при kbps > 0 ещё и
// оценка полосы GCC на стороне отправителя (REQ-N-03): номера TWCC в RTP, клиент (браузер, pion) отвечает
// отчётами о времени прихода, GCC видит рост очереди до потерь. Оценщик сессии приходит в канал.
// ponytail: без пейсера — ключевой кадр уходит пачкой, как и раньше; с пейсером он ждал бы в очереди
// на скорости оценки (+сотни мс). Пейсер — если пачки IDR будут переполнять буферы на узких каналах.
func newAPI(se webrtc.SettingEngine, kbps int) (*webrtc.API, chan cc.BandwidthEstimator, *pacer, error) {
	m := &webrtc.MediaEngine{}
	if err := m.RegisterDefaultCodecs(); err != nil {
		return nil, nil, nil, err
	}
	ir := &interceptor.Registry{}
	bwe := make(chan cc.BandwidthEstimator, 1)
	if kbps > 0 {
		f, err := cc.NewInterceptor(func() (cc.BandwidthEstimator, error) {
			return gcc.NewSendSideBWE(gcc.SendSideBWEInitialBitrate(kbps*1000), gcc.SendSideBWEMaxBitrate(kbps*1000),
				gcc.SendSideBWEMinBitrate(rateMin*1000), gcc.SendSideBWEPacer(gcc.NewNoOpPacer()))
		})
		if err != nil {
			return nil, nil, nil, err
		}
		f.OnNewPeerConnection(func(_ string, e cc.BandwidthEstimator) {
			select {
			case bwe <- e:
			default:
			}
		})
		ir.Add(f)
		if err := webrtc.ConfigureTWCCHeaderExtensionSender(m, ir); err != nil {
			return nil, nil, nil, err
		}
	}
	if err := webrtc.RegisterDefaultInterceptors(m, ir); err != nil {
		return nil, nil, nil, err
	}
	pace := &pacer{} // последним — ближе всех к приложению (pace.go)
	pace.kbps.Store(int64(kbps))
	ir.Add(pace)
	return webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithInterceptorRegistry(ir), webrtc.WithSettingEngine(se)), bwe, pace, nil
}

// vp9 — кодер VP9 в процессе (по запросу клиента и если собран), иначе H.264 через ffmpeg.
func (a *Agent) newSession(ctx context.Context, c *websocket.Conn, cid string, ice []webrtc.ICEServer, om offerMsg, vp9, view bool) (*session, error) {
	kbps := 0
	if a.Capture != nil {
		kbps = a.Bitrate
	}
	api, bwe, pace, err := newAPI(webrtc.SettingEngine{}, kbps)
	if err != nil {
		return nil, err
	}
	pc, err := api.NewPeerConnection(webrtc.Configuration{ICEServers: ice})
	if err != nil {
		select { // оценщик создаётся раньше, чем NewPeerConnection может упасть, — закрыть его горутины
		case e := <-bwe:
			e.Close()
		default:
		}
		return nil, err
	}
	fail := func(err error) (*session, error) { pc.Close(); return nil, err }
	codec := webrtc.RTPCodecCapability{
		MimeType: webrtc.MimeTypeH264, ClockRate: 90000,
		SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
	}
	if vp9 {
		codec = webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP9, ClockRate: 90000, SDPFmtpLine: "profile-id=0"}
	}
	track, err := webrtc.NewTrackLocalStaticSample(codec, "video", "anypc")
	if err != nil {
		return fail(err)
	}
	sender, err := pc.AddTrack(track)
	if err != nil {
		return fail(err)
	}
	s := &session{cid: cid, conn: c, pc: pc, mons: listMonitors(), vp9: vp9, pace: pace}
	s.view.Store(view)
	if kbps > 0 {
		s.rate = rate{max: kbps, cur: kbps, fpsMax: a.FPS}
		select { // фабрика интерсептора вызывается внутри NewPeerConnection — оценщик уже здесь
		case s.bwe = <-bwe:
		default:
		}
	}
	go readRTCP(sender, s.onRTCP)
	s.mon = primaryIndex(s.mons)
	sctx, cancel := context.WithCancel(ctx)
	fail = func(err error) (*session, error) { cancel(); pc.Close(); return nil, err }
	if err := a.authChannel(sctx, s, track); err != nil {
		return fail(err)
	}
	dc, err := pc.CreateDataChannel("input", nil) // надёжный, упорядоченный
	if err != nil {
		return fail(err)
	}
	bad := 0
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if !s.control() {
			return
		}
		e, err := decode(msg.Data)
		if err == nil {
			s.keys.track(e)
			if s.keys.copyKey(e) {
				s.copied.Store(true)
			}
			err = sendInput(e, s.monitor())
		}
		if err != nil && bad < 10 { // не забивать журнал
			bad++
			log.Printf("ввод: %v", err)
		}
	})

	ctl, err := pc.CreateDataChannel("ctl", nil)
	if err != nil {
		return fail(err)
	}
	ctl.OnMessage(func(msg webrtc.DataChannelMessage) {
		var m ctlMsg
		if !s.authed.Load() || json.Unmarshal(msg.Data, &m) != nil {
			return
		}
		switch {
		case m.T == "clip" && s.control() && s.clip.fromRemote(m.Text):
			if err := setClip(m.Text); err != nil {
				log.Printf("буфер обмена: %v", err)
			}
		case m.T == "audio" && m.SDP != "" && a.Audio:
			s.audioOffer(m.SDP)
		case m.T == "monitor":
			if s.selectMonitor(m.I) {
				log.Printf("сессия %s: монитор %d", s.cid, m.I+1)
			}
		case m.T == "quality":
			if s.setVideo(m.P == "video") {
				log.Printf("сессия %s: профиль «%s»", s.cid, m.P)
			}
		case m.T == "pick" && s.control() && s.picking.CompareAndSwap(false, true): // одно окно выбора за раз
			go func() {
				path, ok := pickFile()
				s.picking.Store(false)
				if ok {
					if err := sendFile(sctx, pc, path); err != nil {
						log.Printf("отправка %s: %v", path, err)
					}
				}
			}()
		}
	})
	s.ctl = ctl
	ctl.OnOpen(func() {
		go s.watchClip(sctx, func(b []byte) { ctl.SendText(string(b)) })
		go s.watchCursor(sctx, func(b []byte) { ctl.SendText(string(b)) })
		s.sendMonitors()
		s.sendState()
	})
	recv := new(atomic.Int32) // идущие приёмы файлов этой сессии (не больше maxRecv)

	pc.OnDataChannel(func(dc *webrtc.DataChannel) { a.clientChannel(s, dc, recv) })
	var started, ended sync.Once
	// Кандидаты до отправки offer копятся: клиент без offer их выбросит (найдено -race в TestE2E).
	var (
		cmu       sync.Mutex
		pending   []webrtc.ICECandidateInit
		offerSent bool
	)
	pc.OnICECandidate(func(ci *webrtc.ICECandidate) {
		if ci == nil {
			return
		}
		cmu.Lock()
		if !offerSent {
			pending = append(pending, ci.ToJSON())
			cmu.Unlock()
			return
		}
		cmu.Unlock()
		a.send(ctx, c, "ice", cid, ci.ToJSON())
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		log.Printf("сессия %s: %s", cid, st)
		switch st {
		case webrtc.PeerConnectionStateConnected:
			started.Do(func() {
				if p, err := sender.Transport().ICETransport().GetSelectedCandidatePair(); err == nil && p != nil {
					log.Printf("путь: %s → %s", p.Local.Typ, p.Remote.Typ) // relay = через TURN
					s.mu.Lock()
					s.peer = p.Remote.Address
					if p.Remote.Typ == webrtc.ICECandidateTypeRelay || p.Local.Typ == webrtc.ICECandidateTypeRelay {
						s.peer += " (relay)"
					}
					s.mu.Unlock()
				}
			})
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			ended.Do(func() {
				cancel()
				for _, e := range s.keys.release() { // не оставить зажатый Ctrl/кнопку на хосте
					sendInput(e, nil)
				}
				s.mu.Lock()
				if s.closeInd != nil {
					s.closeInd()
				}
				s.mu.Unlock()
				go pc.Close()
				a.release(s)
				a.notify()
			})
		}
	})
	offer, err := pc.CreateOffer(nil)
	if err == nil {
		err = pc.SetLocalDescription(offer)
	}
	if err != nil {
		return fail(err)
	}
	om.SessionDescription = offer
	a.send(ctx, c, "offer", cid, om)
	cmu.Lock()
	offerSent = true
	early := pending
	pending = nil
	cmu.Unlock()
	for _, ci := range early {
		a.send(ctx, c, "ice", cid, ci)
	}
	return s, nil
}

// authChannel: CPace по каналу "auth" после установления DTLS; при успехе — плашка, видео.
// Без входа за authWait сессия закрывается; код TOTP ждём otpWait90 на каждый запрос, по сроку — "denied".
func (a *Agent) authChannel(ctx context.Context, s *session, track *webrtc.TrackLocalStaticSample) error {
	ch, err := s.pc.CreateDataChannel("auth", nil)
	if err != nil {
		return err
	}
	var st *cpace.State
	var fpClient, fpHost string
	named, view := false, false                                                 // клиент уже назвал имя записи (одно на сессию); права записи «просмотр»
	var otpWait func(code string)                                               // ждём код TOTP (под s.mu); nil — не ждём
	otpN := 0                                                                   // номер запроса кода: таймер закрывает сессию, только если на этот запрос не ответили
	send := func(m authMsg) { b, _ := json.Marshal(m); ch.SendText(string(b)) } // JSON — текстом: браузер парсит строку
	ch.OnOpen(func() {
		s.mu.Lock()
		fpHost, fpClient = pake.Fingerprint(s.pc.LocalDescription().SDP), pake.Fingerprint(s.pc.RemoteDescription().SDP)
		s.mu.Unlock()
		salt, msgA, state, v, err := a.userStart("", fpClient, fpHost) // запись по умолчанию: старый клиент без имени
		if err != nil {
			log.Printf("вход: %v", err)
			s.pc.Close()
			return
		}
		s.mu.Lock()
		st, view, s.salt = state, v, salt
		s.mu.Unlock()
		send(authMsg{T: "a", Salt: salt, Msg: msgA, Users: true})
	})
	ch.OnMessage(func(msg webrtc.DataChannelMessage) {
		var m authMsg
		bad := json.Unmarshal(msg.Data, &m) != nil
		if !bad && m.T == "a" { // REQ-S-20: клиент назвал запись — CPace заново с её солью (до "b", один раз)
			s.mu.Lock()
			ok := st != nil && !named && len(m.User) <= maxUserLen && !strings.ContainsFunc(m.User, unicode.IsControl)
			named, st = true, nil
			fpc, fph := fpClient, fpHost
			s.mu.Unlock()
			if !ok { // второе имя, имя после "b" или негодное — нарушение протокола: вход на этом соединении кончен
				s.pc.Close()
				return
			}
			user := UserKey(m.User)
			salt, msgA, state, v, err := a.userStart(user, fpc, fph)
			if err != nil {
				log.Printf("вход: %v", err)
				s.pc.Close()
				return
			}
			s.mu.Lock()
			st, view, s.user, s.salt = state, v, user, salt
			s.mu.Unlock()
			send(authMsg{T: "a", Salt: salt, Msg: msgA, User: m.User})
			return
		}
		if !bad && m.T == "otp" {
			s.mu.Lock()
			f := otpWait
			otpWait = nil // один ответ на запрос
			s.mu.Unlock()
			if f != nil {
				f(m.Code)
			}
			return
		}
		s.mu.Lock()
		cur, fpc, fph, user, uview := st, fpClient, fpHost, s.user, view
		st = nil // одна попытка на сессию
		s.mu.Unlock()
		if cur == nil || bad || m.T != "b" {
			return
		}
		keyOK := pake.ClientVerify(m.CPub, m.CSig, a.ID, fpc, fph)      // клиент владеет ключом cpub
		trusted := keyOK && a.Trusted != nil && a.Trusted(m.CPub, user) // ключ закреплён за этой записью: права другой записи он не перебирает
		reject := func(t string) {
			send(authMsg{T: t})
			a.release(s) // освободить сразу: повтор не должен получить «занят»

			time.AfterFunc(500*time.Millisecond, func() { s.pc.Close() }) // дать дойти ответу
		}
		// блокировка (REQ-S-04, по имени и по хосту — REQ-S-22) — только для чужих; проверка и счёт под одним a.mu:
		// параллельные входы не проскочат блокировку все сразу (HostFinish дешёвый — KDF посчитан заранее)
		unattended := a.Confirm == nil || a.Unattended != nil && a.Unattended()
		otpSet := false
		if unattended && a.OTP != nil {
			otpSet, _ = a.OTP(user, "")
		}
		a.mu.Lock()
		if !trusted && a.pwLocked(user, time.Now()) {
			a.mu.Unlock()
			reject("locked")
			return
		}
		conf, err := pake.HostFinish(cur, m.Msg, m.Conf)
		// ponytail: опечатки доверенного не считаются — украденный ключ даёт перебор без блокировки; счётчик для доверенных, если понадобится.
		// С TOTP верный пароль счётчик не сбрасывает: иначе вор пароля чередовал бы его с перебором кода мимо блокировки.
		if !trusted && (err != nil || !otpSet) {
			a.countAuth(s.cid, user, err == nil)
		}
		a.mu.Unlock()
		if err != nil {
			reject("fail")
			return
		}
		if uview { // права записи «просмотр» (REQ-S-20 = REQ-F-20): хост ставит сам, клиент не расширит
			s.view.Store(true)
		}
		var pin []byte // закрепить ключ клиента — только когда вход разрешён (и человеком на хосте, REQ-F-03)
		if keyOK && !trusted {
			pin = m.CPub
		}
		if !a.promote(s) { // пароль верный, но другой вход успел раньше
			reject("busy")
			return
		}
		if unattended && a.OTP == nil { // TOTP нет вовсе (встраивание без него) — как раньше
			a.accept(ctx, s, track, send, conf, fpc, fph, pin)
			return
		}
		noOTP := unattended && !otpSet // без подтверждения, а у записи TOTP не настроен (хост после обновления) — спросить человека
		if noOTP && a.Confirm == nil {
			reject("denied")
			return
		}
		if otpSet { // PLAN.md «TOTP»: код после пароля внутри канала; до верного кода — ни видео, ни ввода, ни файлов
			s.asking.Store(true) // общий таймер входа не закрывает — у каждого запроса кода свой
			var ask func()
			check := func(code string) {
				// Блокировка (REQ-S-04, S-22): у записи своя лестница кодов (5 → 1 мин … 1 ч), её сбрасывает только верный
				// код этой же записи (вор с паролем и ключом записи получает 5 кодов, как в v0.1.19, и свой вход другой
				// записью их не обнуляет) — её смотрят все. Чужой смотрит ещё общую лестницу кодов по хосту и блокировки
				// паролей; закреплённый ключ — нет (У3: ни перебор паролей, ни неверные коды записи «просмотр» со своим TOTP
				// владельца с ключом не запирают).
				lock := func() bool {
					now := time.Now()
					n := a.nameOf(user, false)
					return !trusted && now.Before(a.otpLock) || n != nil && now.Before(n.otpUntil) || !trusted && a.pwLocked(user, now)
				}
				a.mu.Lock()
				if lock() {
					a.mu.Unlock()
					reject("locked")
					return
				}
				_, ok := a.OTP(user, code)
				if n := a.names[user]; ok && n != nil { // своя запись, не общий othersKey
					n.otpFails = 0
				} else if !ok {
					n := a.nameOf(user, true)
					lockStep(&n.otpFails, &n.otpUntil, 5)
					n.at = time.Now()
					hostStep(&a.otpFails, &a.otpLock, &a.otpAt)
				}
				if !trusted || !ok { // неверные коды — и в общий счётчик (REQ-S-04); успех ключа общий не сбрасывает
					a.countAuth(s.cid, user, ok)
				}
				locked := lock()
				a.mu.Unlock()
				switch {
				case ctx.Err() != nil: // клиент ушёл
				case ok:
					s.asking.Store(false)
					a.accept(ctx, s, track, send, conf, fpc, fph, pin)
				case locked:
					reject("locked")
				default:
					log.Printf("сессия %s: неверный код TOTP", s.cid)
					ask()
				}
			}
			ask = func() {
				s.mu.Lock()
				otpWait = check
				otpN++
				n := otpN
				s.mu.Unlock()
				// conf и подпись — как в "ok": клиент отдаёт код только хосту, доказавшему пароль и ключ (не хабу-самозванцу)
				send(authMsg{T: "otp", Conf: conf, Pub: a.Key.Public().(ed25519.PublicKey), Sig: pake.HostSign(a.Key, a.ID, fpc, fph)})
				wait := time.Duration(otpWait90.Load())
				time.AfterFunc(wait, func() {
					s.mu.Lock()
					waiting := otpN == n && otpWait != nil
					if waiting {
						otpWait = nil // код, пришедший следом, уже не проверяется: нет «ok» и тут же разрыва
					}
					s.mu.Unlock()
					if waiting && !s.authed.Load() { // внятный отказ (и старому клиенту), а не обрыв связи
						log.Printf("сессия %s: код TOTP не введён за %v", s.cid, wait)
						reject("denied")
					}
				})
			}
			ask()
			return
		}
		// REQ-F-03: пароль верный — теперь спросить человека на хосте (до 30 с; ответ не держит канал)
		s.asking.Store(true)
		send(authMsg{T: "ask", NoOTP: noOTP})
		go func() {
			s.mu.Lock()
			peer := s.peer
			s.mu.Unlock()
			ans := a.Confirm(s.label(), peer)
			s.asking.Store(false)
			switch {
			case ctx.Err() != nil: // клиент ушёл, пока ждали ответа
			case ans != Deny:
				if ans == ViewOnly { // человек на хосте может только сузить права, не расширить
					s.view.Store(true)
				}
				a.accept(ctx, s, track, send, conf, fpc, fph, pin)
			default:
				log.Printf("сессия %s: отклонена на хосте", s.cid)
				reject("denied")
			}
		}()
	})
	time.AfterFunc(authWait, func() {
		if !s.authed.Load() && !s.asking.Load() {
			s.pc.Close()
		}
	})
	return nil
}

// authWait — сколько ждать входа после открытия канала auth; otpWait90 — кода TOTP на каждый запрос (разблокировать
// телефон, открыть приложение, найти запись, набрать 6 цифр).
// otpWait90 — атомарно (нс): тесты меняют его при живых сессиях.
var authWait = 20 * time.Second
var otpWait90 atomic.Int64

func init() { otpWait90.Store(int64(90 * time.Second)) }

// accept — вход разрешён: подпись хоста, плашка сессии, видео.
func (a *Agent) accept(ctx context.Context, s *session, track *webrtc.TrackLocalStaticSample, send func(authMsg), conf []byte, fpc, fph string, pin []byte) {
	if a.ViewOnly != nil && a.ViewOnly() { // хост сужает права сам — и «Разрешить» в окне даёт только просмотр
		s.view.Store(true)
	}
	s.authed.Store(true)
	// ещё раз после authed: галочку могли включить между проверкой выше и authed, а DisconnectFull не вошедшую не рвёт
	if a.ViewOnly != nil && a.ViewOnly() {
		s.view.Store(true)
	}
	// и запись: её могли удалить или сменить ей пароль, пока ждали «Разрешить» или код, — DropRevoked не вошедшую не рвёт,
	// а на Windows опроса настроек нет; права сузили — только просмотр
	if gone, v := a.revoked(s); gone {
		log.Printf("сессия %s: учётную запись удалили или сменили ей пароль во время входа — отказ", s.label())
		s.pc.Close()
		return
	} else if v {
		s.view.Store(true)
	}
	if pin != nil && a.Trust != nil {
		a.Trust(pin, s.user)
	}
	view := s.view.Load()
	send(authMsg{T: "ok", Conf: conf, Pub: a.Key.Public().(ed25519.PublicKey), Sig: pake.HostSign(a.Key, a.ID, fpc, fph), View: view, Audio: a.Audio})
	log.Printf("сессия %s: вход выполнен%s", s.label(), map[bool]string{true: " (только просмотр)"}[view]) // REQ-F-16, F-24
	s.sendMonitors()
	closeInd, err := showIndicator(s.label(), s.plaque(), a.userClose(s)) // REQ-F-15, F-24
	if err != nil {                                                       // REQ-S-08: без видимой плашки сессии нет
		log.Printf("плашка сессии: %v — сессия закрыта", err)
		s.pc.Close()
		return
	}
	s.mu.Lock()
	s.closeInd = closeInd
	if ctx.Err() != nil || s.gone.Load() { // сессия кончилась, пока открывалась плашка: ended её уже не закроет
		s.closeInd = nil
		s.mu.Unlock()
		closeInd()
		return
	}
	s.mu.Unlock()
	a.notify()
	go a.stream(ctx, s, track)
}

// label — клиент для плашки, окна «Разрешить», окна хоста и журнала: ID и имя записи (REQ-F-24). Имя — из настроек
// хоста (UserKey существующей записи: проверенные символы), не строка клиента; плашка Linux экранирует Pango сама.
func (s *session) label() string {
	if s.user == "" {
		return s.cid
	}
	return s.cid + " · " + s.user
}

// Answer — ответ человека на хосте в окне «Разрешить» (REQ-F-03).
type Answer int

const (
	Deny     Answer = iota
	Allow           // полное управление
	ViewOnly        // REQ-F-20: только просмотр
)

// clientChannel — канал, открытый клиентом: только файлы и только после входа. В «только просмотр» — внятный отказ:
// клиенты ≤ v0.1.15 кнопку файлов не прячут, а молча закрытый канал они показывали как обрыв «отправьте ещё раз».
func (a *Agent) clientChannel(s *session, dc *webrtc.DataChannel, recv *atomic.Int32) {
	switch {
	case dc.Label() == "file" && s.control():
		a.receiveFile(dc, recv)
	case dc.Label() == "file" && s.authed.Load():
		dc.OnOpen(func() {
			sendJSON(dc, fileMsg{T: "err", Msg: "только просмотр: файлы на этот ПК не принимаются"})
			dc.Close()
		})
	default:
		dc.OnOpen(func() { dc.Close() })
	}
}

// control — от клиента можно принимать ввод, буфер обмена и файлы: вход выполнен и сессия не «только просмотр».
func (s *session) control() bool { return s.authed.Load() && !s.view.Load() }

// userClose — человек закрыл плашку сессии s: разорвать её, но не следующую (плашка могла пережить свою сессию).
func (a *Agent) userClose(s *session) func() {
	return func() {
		if a.byCID(s.cid) == s {
			a.Disconnect()
		}
	}
}

// sendMonitors — список мониторов клиенту: только после входа (имена и разрешения — тоже сведения о хосте)
// и когда канал ctl открыт; зовут оба события, повтор безвреден.
func (s *session) sendMonitors() {
	if !s.authed.Load() || s.ctl == nil || s.ctl.ReadyState() != webrtc.DataChannelStateOpen {
		return
	}
	s.mu.Lock()
	b, _ := json.Marshal(ctlMsg{T: "monitors", List: s.mons, Cur: s.mon})
	s.mu.Unlock()
	s.ctl.SendText(string(b))
}

// clipSeq, clipText — системный буфер (подменяются в тестах).
var clipSeq, clipText, setClip = ClipSeq, ClipText, SetClipText

// clipOnCopy — читать буфер хоста только после Ctrl+C/X клиента, а не опросом. Wayland (linux.go): у GNOME нет
// data-control, и каждый wl-paste создаёт окно и забирает фокус — опрос раз в 0,5 с дёргал док, тормозил ввод
// у человека за хостом и сворачивал выпадающие списки (владелец, 2026-11-11). Скопированное мышью через меню
// клиенту не уйдёт. ponytail: буфер через портал RemoteDesktop (Clipboard) — если этого окажется мало.
var clipOnCopy atomic.Bool // атомарно: тесты меняют его, пока watchClip прошлой сессии ещё читает

// ClipCheap — буфер обмена можно опрашивать без побочных эффектов (не Wayland): для программы-клиента (app).
func ClipCheap() bool { return !clipOnCopy.Load() }

// watchClip отправляет клиенту изменения буфера обмена хоста (только изменения после начала сессии).
// Д-5: до успешного входа — ничего: иначе любой, кто знает ID, читал бы буфер хоста 20 с ожидания пароля.
func (s *session) watchClip(ctx context.Context, send func([]byte)) {
	seq := clipSeq()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	recheck := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if clipOnCopy.Load() { // через 0,5, 1 и 1,5 с после Ctrl+C: приложение кладёт текст в буфер не сразу
			if s.copied.Swap(false) {
				recheck = 3
			}
			if recheck == 0 {
				continue
			}
			recheck--
		}
		if n := clipSeq(); n != seq {
			seq = n
			if !s.authed.Load() || s.view.Load() {
				continue
			}
			if text, err := clipText(); err == nil && s.clip.toRemote(text) {
				b, _ := json.Marshal(ctlMsg{T: "clip", Text: text})
				send(b)
			}
		}
	}
}

// ErrCaptureDenied — человек у хоста отказал в доступе к экрану (Wayland: «Отмена» в окне портала). Повторять бессмысленно:
// окно всплывало бы снова каждые 2 с — сессия закрывается, клиент видит причину (state "denied").
var ErrCaptureDenied = errors.New("доступ к экрану отклонён на удалённом ПК")

// lockPoll — как часто проверять заблокированный экран; noFramePause — пауза перед повтором захвата, не давшего
// ни кадра (экран блокировки, UAC, отказ портала): без неё ffmpeg перезапускался каждые 300 мс без конца (F7).
var lockPoll, noFramePause = 2 * time.Second, 2 * time.Second

// stateEvery — не чаще чем раз в столько повторять клиенту текущее состояние, пока оно держится (D3).
// Атомарно (нс): тесты меняют его при живых сессиях.
var stateEvery atomic.Int64

func init() { stateEvery.Store(int64(2 * time.Second)) }

func (a *Agent) stream(ctx context.Context, s *session, track *webrtc.TrackLocalStaticSample) {
	for {
		if a.Locked != nil && a.Locked() { // macOS: на заблокированном экране ffmpeg кадров не даст — не запускать
			s.setState("locked")
			log.Printf("сессия %s: экран заблокирован — жду разблокировки", s.cid)
			for a.Locked() {
				select {
				case <-ctx.Done():
					return
				case <-time.After(lockPoll):
				}
				s.repeatState()
			}
			s.refreshMonitors() // при блокировке список мониторов мог быть пуст или другим
		} else if s.noMonitors() { // D4: сразу после разблокировки дисплеи могли ещё не проснуться — снимать, пока пусто
			s.refreshMonitors()
		}
		got := a.streamOnce(ctx, s, track, func() { s.setState("ok") })
		if s.denied.Load() {
			s.setState("denied")
			log.Printf("сессия %s: доступ к экрану отклонён на хосте — сессия закрыта", s.cid)
			time.Sleep(200 * time.Millisecond) // state по ctl — раньше, чем bye через хаб
			a.send(context.Background(), s.conn, "bye", s.cid, "host")
			s.pc.Close()
			return
		}
		if ctx.Err() == nil && s.switched.Swap(false) {
			continue // смена монитора — сразу
		}
		// ffmpeg завершился сам — обычно DXGI_ERROR_ACCESS_LOST (887a0026): UAC, блокировка,
		// полноэкранное окно, смена режима (ТЗ §9). Перезапуск отдаёт браузеру новый IDR.
		pause := 300 * time.Millisecond
		if !got && ctx.Err() == nil {
			pause = noFramePause
			if s.setState("nocapture") {
				log.Printf("сессия %s: захват не дал ни кадра — повтор раз в %v", s.cid, noFramePause)
			} else {
				s.repeatState()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pause):
			if got {
				log.Printf("перезапуск захвата")
			}
		}
	}
}

// setState — состояние захвата для клиента (F7); true — изменилось. Начальное «ok» не шлётся: клиент его и так предполагает.
func (s *session) setState(st string) bool {
	s.mu.Lock()
	if s.state == st || s.state == "" && st == "ok" {
		s.mu.Unlock()
		return false
	}
	s.state, s.stateAt = st, time.Now()
	s.mu.Unlock()
	s.sendState()
	return true
}

// repeatState — повторить клиенту текущее состояние (не чаще stateEvery). Первое могло потеряться: ok входа идёт
// по каналу auth, state — по ctl, порядок между каналами не гарантирован, а клиент принимает state только после входа.
func (s *session) repeatState() {
	s.mu.Lock()
	due := time.Since(s.stateAt) >= time.Duration(stateEvery.Load())
	if due {
		s.stateAt = time.Now()
	}
	s.mu.Unlock()
	if due {
		s.sendState()
	}
}

// sendState — состояние захвата клиенту: только после входа (иначе состояние экрана узнаёт любой, кто знает ID)
// и при открытом ctl; зовут setState и открытие ctl.
func (s *session) sendState() {
	if !s.authed.Load() || s.ctl == nil || s.ctl.ReadyState() != webrtc.DataChannelStateOpen {
		return
	}
	s.mu.Lock()
	st := s.state
	s.mu.Unlock()
	if st == "" {
		return
	}
	b, _ := json.Marshal(ctlMsg{T: "state", S: st})
	s.ctl.SendText(string(b))
}

// refreshMonitors — заново снять список мониторов (после разблокировки) и послать клиенту.
// Пусто и было пусто (Wayland — всегда) — клиенту не слать.
func (s *session) refreshMonitors() {
	ms := listMonitors()
	s.mu.Lock()
	same := len(ms) == 0 && len(s.mons) == 0
	s.mons = ms
	if s.mon >= len(ms) {
		s.mon = primaryIndex(ms)
	}
	s.mu.Unlock()
	if !same {
		s.sendMonitors()
	}
}

// noMonitors — список мониторов пуст: координаты мыши не пересчитываются, выбора монитора нет.
func (s *session) noMonitors() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.mons) == 0
}

// streamVP9 — кадры Y4M из ffmpeg → libvpx в процессе → трек. Битрейт и частота кадров берутся из rate на каждом
// кадре (прореживание кадров источника), ключевой кадр — по keyReq (PLI): ничего из этого не перезапускает ffmpeg.
// onFrame зовётся на первом отправленном кадре; true — кадр был.
func (a *Agent) streamVP9(ctx context.Context, s *session, out io.Reader, track *webrtc.TrackLocalStaticSample, c Cap, onFrame func()) (got bool) {
	y, err := newY4M(out)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("%v", err)
		}
		return
	}
	enc, err := newVP9(y.w, y.h, c.Kbps)
	if err != nil {
		log.Printf("%v", err)
		return
	}
	defer enc.close()
	s.inproc.Store(true)
	s.mu.Lock()
	s.rate.fast = true
	s.mu.Unlock()
	defer func() { s.inproc.Store(false); s.mu.Lock(); s.rate.fast = false; s.mu.Unlock() }()
	log.Printf("vp9: %d×%d, источник %d к/с", y.w, y.h, y.fps)
	acc := 0.0                // прореживание: кадр уходит, когда накопилась единица целевой частоты
	var skipped time.Duration // длительность кадров с последней отправки (пропущенные кодером + текущий)
	for {
		frame, err := y.next()
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("поток: %v", err)
			}
			return
		}
		s.mu.Lock()
		kbps, fps := s.rate.cur, s.rate.fps()
		s.mu.Unlock()
		if fps <= 0 || fps > y.fps {
			fps = y.fps
		}
		if acc += float64(fps) / float64(y.fps); acc < 1 {
			continue
		}
		acc--
		if err := enc.setRate(kbps, fps); err != nil {
			log.Printf("%v", err)
		}
		dur := time.Second / time.Duration(fps)
		key := s.keyReq.Swap(false)
		data, _, err := enc.encode(frame, dur, key)
		if err != nil {
			log.Printf("%v", err)
			return
		}
		skipped += dur
		if data == nil { // пропущен кодером: время кадра уходит в метку следующего
			s.keyReq.CompareAndSwap(false, key)
			continue
		}
		if err := track.WriteSample(media.Sample{Data: data, Duration: skipped}); err != nil {
			return
		}
		if !got {
			got = true
			onFrame()
		}
		skipped = 0
	}
}

// streamOnce: ffmpeg пишет H.264 Annex-B в stdout, NAL-юниты уходят в трек (или Y4M → streamVP9).
// ponytail: h264reader отдаёт NAL только по старт-коду следующего → +1 кадр задержки (33 мс при 30 к/с);
// убрать — читать пакеты из контейнера (nut/mkv) или кодировать в процессе.
// onFrame зовётся на первом отправленном кадре; true — кадр был (F7: захват без единого кадра повторяется с паузой).
func (a *Agent) streamOnce(ctx context.Context, s *session, track *webrtc.TrackLocalStaticSample, onFrame func()) (got bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.mu.Lock()
	s.capCancel, s.capStart = cancel, time.Now()
	c := Cap{Mon: s.mon, Kbps: s.rate.cur, FPS: s.rate.fps(), Video: s.rate.video, Cursor: cursorInfo == nil, VP9: s.vp9}
	s.mu.Unlock()
	if c.FPS <= 0 || s.vp9 { // без адаптации (FF из тестов) — как задано; VP9: источник всегда на полной частоте,
		c.FPS = a.FPS // до rate.fps() прореживает streamVP9 — иначе после перезапуска источник застревал на 5 к/с
	}
	var cmd *exec.Cmd
	if a.Capture != nil {
		var err error
		if cmd, err = a.Capture(ctx, c); err != nil {
			log.Printf("захват: %v", err)
			s.denied.Store(errors.Is(err, ErrCaptureDenied))
			return
		}
	} else {
		cmd = exec.CommandContext(ctx, "ffmpeg", a.FF...)
	}
	hideWindow(cmd)
	cmd.Stderr = a.Stderr
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	out, err := cmd.StdoutPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		log.Printf("ffmpeg: %v", err)
		return
	}
	defer func() { cancel(); cmd.Wait() }() // сначала убить: при выходе по ошибке записи ffmpeg жив, а пайп никто не читает
	if s.vp9 {
		return a.streamVP9(ctx, s, out, track, c, onFrame)
	}
	r, err := h264reader.NewReader(out)
	if err != nil {
		log.Printf("h264: %v", err)
		return
	}
	frame := time.Second / time.Duration(c.FPS)
	for {
		nal, err := r.NextNAL()
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("поток: %v", err)
			}
			return
		}
		d := time.Duration(0) // SPS/PPS/SEI делят метку времени со следующим слайсом
		if nal.UnitType == h264reader.NalUnitTypeCodedSliceIdr || nal.UnitType == h264reader.NalUnitTypeCodedSliceNonIdr {
			d = frame
		}
		if err := track.WriteSample(media.Sample{Data: nal.Data, Duration: d}); err != nil {
			return
		}
		if d != 0 && !got {
			got = true
			onFrame()
		}
	}
}
