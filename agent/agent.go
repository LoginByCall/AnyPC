// Package agent — хост: регистрация на сервере, проверка пароля, захват экрана ffmpeg → H.264 → WebRTC,
// приём ввода по каналу данных "input".
package agent

import (
	"context"
	"crypto/ed25519"
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
	Server  string                       // wss://…/ws; несколько хабов — через запятую (хост в сети на каждом)
	ID      string                       // 9 цифр
	Secret  func() (salt, secret []byte) // соль и KDF(пароль, соль) из настроек; пустой secret — пароль не задан
	Key     ed25519.PrivateKey           // ключ хоста: за ним закреплён ID (REQ-F-01), им хост подтверждает себя клиенту
	FF      []string                     // аргументы ffmpeg, см. FFArgs
	FPS     int
	Stderr  io.Writer                                           // вывод ffmpeg; nil — os.Stderr
	OnState func(online bool, session string)                   // session "" — сессии нет
	FileDir string                                              // куда принимать файлы; "" — DownloadsDir()
	Capture func(ctx context.Context, c Cap) (*exec.Cmd, error) // захват по Cap (H.264 Annex-B или Y4M в stdout); nil — FFmpeg + FF
	Bitrate int                                                 // кбит/с — потолок адаптивного битрейта (REQ-N-03); 0 — постоянный
	Confirm func(cid, peer string) Answer                       // REQ-F-03: спросить человека на хосте после верного пароля; nil — не спрашивать (unattended)
	Trusted func(pub []byte) bool                               // У3: ключ клиента закреплён (вход с ним был); nil — без доверенных
	Trust   func(pub []byte)                                    // закрепить ключ клиента после входа по паролю

	mu        sync.Mutex
	ice       []webrtc.ICEServer
	rtt       map[string]int       // мс от хоста до каждого TURN (замер по hello, не чаще measureEvery)
	rttAt     map[string]time.Time // когда мерили этот набор TURN
	sess      *session             // сессия с верным паролем (одна); до него — в pend
	pend      map[*session]bool    // незавершённые входы: не больше maxPending, «занят» — только при sess
	starting  int                  // занятые места pend, пока newSession шлёт offer (без a.mu)
	fails     int
	lockUntil time.Time
	online    map[string]bool // хабы, на которых хост зарегистрирован
}

type session struct {
	cid     string
	conn    *websocket.Conn // хаб, через который пришёл клиент
	pc      *webrtc.PeerConnection
	keys    held
	clip    clipSync
	authed  atomic.Bool // до успешного CPace ни видео, ни ввод, ни буфер обмена, ни файлы не работают
	view    atomic.Bool // REQ-F-20 «только просмотр»: от клиента — ни ввода, ни буфера, ни файлов; буфер хоста ему не уходит
	picking atomic.Bool // открыто окно выбора файла
	asking  atomic.Bool // на хосте открыто окно «Разрешить / Отклонить»
	gone    atomic.Bool // сессия освобождена (release) — в pend не возвращать
	ctl     *webrtc.DataChannel
	peer    string // адрес клиента по выбранной паре ICE — для окна подтверждения

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
type authMsg struct {
	T    string `json:"t"`
	Salt []byte `json:"salt,omitempty"`
	Msg  []byte `json:"msg,omitempty"`
	Conf []byte `json:"conf,omitempty"`
	Pub  []byte `json:"pub,omitempty"` // в "ok": ключ хоста и подпись над DTLS-отпечатками (REQ-S-05)
	Sig  []byte `json:"sig,omitempty"`
	View bool   `json:"view,omitempty"` // в "ok": сессия «только просмотр» (REQ-F-20)
	CPub []byte `json:"cpub,omitempty"` // в "b": ключ клиента и его подпись над DTLS-отпечатками (У3)
	CSig []byte `json:"csig,omitempty"`
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
		cid = a.sess.cid
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
	if a.sess == s {
		a.sess = nil
	}
	delete(a.pend, s)
	a.mu.Unlock()
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
					err = s.pc.SetRemoteDescription(sd)
				}
			case "ice":
				var ci webrtc.ICECandidateInit
				if json.Unmarshal(m.Data, &ci) == nil {
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
	if _, secret := a.Secret(); len(secret) == 0 {
		a.send(ctx, c, "error", m.From, "nopass")
		return
	}
	var req connectReq
	json.Unmarshal(m.Data, &req) // старый клиент шлёт {} — выбора нет, ICE получает все серверы
	trusted := a.Trusted != nil && len(req.CPub) == ed25519.PublicKeySize && a.Trusted(req.CPub)
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
func (a *Agent) authResult(cid string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.countAuth(cid, ok)
}

// countAuth — то же под уже взятым a.mu.
func (a *Agent) countAuth(cid string, ok bool) {
	if ok {
		a.fails = 0
		return
	}
	a.fails++
	if a.fails >= 5 {
		a.lockUntil = time.Now().Add(min(time.Minute<<min(a.fails-5, 6), time.Hour))
	}
	log.Printf("неверный пароль от %s (%d)", cid, a.fails)
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
	})
	recv := new(atomic.Int32) // идущие приёмы файлов этой сессии (не больше maxRecv)

	pc.OnDataChannel(func(dc *webrtc.DataChannel) { // каналы от клиента — только файлы и только после входа
		if dc.Label() == "file" && s.control() {
			a.receiveFile(dc, recv)
			return
		}
		dc.OnOpen(func() { dc.Close() })
	})
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
// Без входа за 20 с сессия закрывается.
func (a *Agent) authChannel(ctx context.Context, s *session, track *webrtc.TrackLocalStaticSample) error {
	ch, err := s.pc.CreateDataChannel("auth", nil)
	if err != nil {
		return err
	}
	var st *cpace.State
	var fpClient, fpHost string
	send := func(m authMsg) { b, _ := json.Marshal(m); ch.SendText(string(b)) } // JSON — текстом: браузер парсит строку
	ch.OnOpen(func() {
		salt, secret := a.Secret()
		s.mu.Lock()
		fpHost, fpClient = pake.Fingerprint(s.pc.LocalDescription().SDP), pake.Fingerprint(s.pc.RemoteDescription().SDP)
		s.mu.Unlock()
		msgA, state, err := pake.HostStart(secret, a.ID, fpClient, fpHost)
		if err != nil {
			log.Printf("вход: %v", err)
			s.pc.Close()
			return
		}
		s.mu.Lock()
		st = state
		s.mu.Unlock()
		send(authMsg{T: "a", Salt: salt, Msg: msgA})
	})
	ch.OnMessage(func(msg webrtc.DataChannelMessage) {
		var m authMsg
		s.mu.Lock()
		cur, fpc, fph := st, fpClient, fpHost
		st = nil // одна попытка на сессию
		s.mu.Unlock()
		if cur == nil || json.Unmarshal(msg.Data, &m) != nil || m.T != "b" {
			return
		}
		keyOK := pake.ClientVerify(m.CPub, m.CSig, a.ID, fpc, fph) // клиент владеет ключом cpub
		trusted := keyOK && a.Trusted != nil && a.Trusted(m.CPub)
		reject := func(t string) {
			send(authMsg{T: t})
			a.release(s) // освободить сразу: повтор не должен получить «занят»

			time.AfterFunc(500*time.Millisecond, func() { s.pc.Close() }) // дать дойти ответу
		}
		// блокировка (REQ-S-04) — только для чужих; проверка и счёт под одним a.mu: параллельные входы
		// не проскочат блокировку все сразу (HostFinish дешёвый — KDF посчитан заранее)
		a.mu.Lock()
		if !trusted && time.Now().Before(a.lockUntil) {
			a.mu.Unlock()
			reject("locked")
			return
		}
		conf, err := pake.HostFinish(cur, m.Msg, m.Conf)
		if !trusted { // ponytail: опечатки доверенного не считаются — украденный ключ даёт перебор без блокировки; счётчик для доверенных, если понадобится
			a.countAuth(s.cid, err == nil)
		}
		a.mu.Unlock()
		if err != nil {
			reject("fail")
			return
		}
		var pin []byte // закрепить ключ клиента — только когда вход разрешён (и человеком на хосте, REQ-F-03)
		if keyOK && !trusted {
			pin = m.CPub
		}
		if !a.promote(s) { // пароль верный, но другой вход успел раньше
			reject("busy")
			return
		}
		if a.Confirm == nil {
			a.accept(ctx, s, track, send, conf, fpc, fph, pin)
			return
		}
		// REQ-F-03: пароль верный — теперь спросить человека на хосте (до 30 с; ответ не держит канал)
		s.asking.Store(true)
		send(authMsg{T: "ask"})
		go func() {
			s.mu.Lock()
			peer := s.peer
			s.mu.Unlock()
			ans := a.Confirm(s.cid, peer)
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
	time.AfterFunc(20*time.Second, func() {
		if !s.authed.Load() && !s.asking.Load() {
			s.pc.Close()
		}
	})
	return nil
}

// accept — вход разрешён: подпись хоста, плашка сессии, видео.
func (a *Agent) accept(ctx context.Context, s *session, track *webrtc.TrackLocalStaticSample, send func(authMsg), conf []byte, fpc, fph string, pin []byte) {
	s.authed.Store(true)
	if pin != nil && a.Trust != nil {
		a.Trust(pin)
	}
	view := s.view.Load()
	send(authMsg{T: "ok", Conf: conf, Pub: a.Key.Public().(ed25519.PublicKey), Sig: pake.HostSign(a.Key, a.ID, fpc, fph), View: view})
	log.Printf("сессия %s: вход выполнен%s", s.cid, map[bool]string{true: " (только просмотр)"}[view])
	s.sendMonitors()
	closeInd, err := showIndicator(s.cid, view, a.userClose(s)) // REQ-F-15
	if err != nil {                                             // REQ-S-08: без видимой плашки сессии нет
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

// Answer — ответ человека на хосте в окне «Разрешить» (REQ-F-03).
type Answer int

const (
	Deny     Answer = iota
	Allow           // полное управление
	ViewOnly        // REQ-F-20: только просмотр
)

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

// watchClip отправляет клиенту изменения буфера обмена хоста (только изменения после начала сессии).
// Д-5: до успешного входа — ничего: иначе любой, кто знает ID, читал бы буфер хоста 20 с ожидания пароля.
func (s *session) watchClip(ctx context.Context, send func([]byte)) {
	seq := clipSeq()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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

func (a *Agent) stream(ctx context.Context, s *session, track *webrtc.TrackLocalStaticSample) {
	for {
		a.streamOnce(ctx, s, track)
		if ctx.Err() == nil && s.switched.Swap(false) {
			continue // смена монитора — сразу
		}
		// ffmpeg завершился сам — обычно DXGI_ERROR_ACCESS_LOST (887a0026): UAC, блокировка,
		// полноэкранное окно, смена режима (ТЗ §9). Перезапуск отдаёт браузеру новый IDR.
		select {
		case <-ctx.Done():
			return
		case <-time.After(300 * time.Millisecond):
			log.Printf("перезапуск захвата")
		}
	}
}

// streamVP9 — кадры Y4M из ffmpeg → libvpx в процессе → трек. Битрейт и частота кадров берутся из rate на каждом
// кадре (прореживание кадров источника), ключевой кадр — по keyReq (PLI): ничего из этого не перезапускает ffmpeg.
func (a *Agent) streamVP9(ctx context.Context, s *session, out io.Reader, track *webrtc.TrackLocalStaticSample, c Cap) {
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
		skipped = 0
	}
}

// streamOnce: ffmpeg пишет H.264 Annex-B в stdout, NAL-юниты уходят в трек (или Y4M → streamVP9).
// ponytail: h264reader отдаёт NAL только по старт-коду следующего → +1 кадр задержки (33 мс при 30 к/с);
// убрать — читать пакеты из контейнера (nut/mkv) или кодировать в процессе.
func (a *Agent) streamOnce(ctx context.Context, s *session, track *webrtc.TrackLocalStaticSample) {
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
		a.streamVP9(ctx, s, out, track, c)
		return
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
	}
}
