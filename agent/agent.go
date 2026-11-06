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
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"anypc/hub"
	"anypc/pake"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/pion/webrtc/v4/pkg/media/h264reader"

	"filippo.io/cpace"
)

type Agent struct {
	Server  string                       // wss://…/ws
	ID      string                       // 9 цифр
	Secret  func() (salt, secret []byte) // соль и KDF(пароль, соль) из настроек; пустой secret — пароль не задан
	Key     ed25519.PrivateKey           // ключ хоста: за ним закреплён ID (REQ-F-01), им хост подтверждает себя клиенту
	FFmpeg  string                       // путь к ffmpeg
	FF      []string                     // аргументы ffmpeg, см. FFArgs
	FPS     int
	Stderr  io.Writer                                                   // вывод ffmpeg; nil — os.Stderr
	OnState func(online bool, session string)                           // session "" — сессии нет
	FileDir string                                                      // куда принимать файлы; "" — %USERPROFILE%\Downloads
	Capture func(ctx context.Context, mon, kbps int) (*exec.Cmd, error) // захват монитора mon с битрейтом kbps (H.264 Annex-B в stdout); nil — FFmpeg + FF
	Bitrate int                                                         // кбит/с — потолок адаптивного битрейта (REQ-N-03); 0 — постоянный
	Confirm func(cid, peer string) bool                                 // REQ-F-03: спросить человека на хосте после верного пароля; nil — не спрашивать (unattended)

	mu        sync.Mutex
	conn      *websocket.Conn
	ice       []webrtc.ICEServer
	sess      *session
	fails     int
	lockUntil time.Time
	online    bool
}

type session struct {
	cid     string
	pc      *webrtc.PeerConnection
	keys    held
	clip    clipSync
	authed  atomic.Bool // до успешного CPace ни видео, ни ввод, ни буфер обмена, ни файлы не работают
	picking atomic.Bool // открыто окно выбора файла
	asking  atomic.Bool // на хосте открыто окно «Разрешить / Отклонить»
	peer    string      // адрес клиента по выбранной паре ICE — для окна подтверждения

	mu        sync.Mutex
	closeInd  func() // закрыть плашку сессии
	mons      []Monitor
	mon       int                // выбранный монитор (индекс в mons)
	capCancel context.CancelFunc // остановить текущий процесс захвата
	switched  atomic.Bool        // захват остановлен ради смены монитора/битрейта — перезапуск без паузы
	rate      rate               // адаптивный битрейт; max == 0 — выключен
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
}

// ctlMsg — канал "ctl": {"t":"clip","text":"…"} — буфер обмена в обе стороны (REQ-F-11);
// {"t":"pick"} от клиента — открыть на хосте окно выбора файла и отправить выбранный (REQ-F-12);
// хост → {"t":"monitors","list":[…],"cur":i}, клиент → {"t":"monitor","i":N} — выбор монитора (REQ-F-09).
type ctlMsg struct {
	T    string    `json:"t"`
	Text string    `json:"text,omitempty"`
	List []Monitor `json:"list,omitempty"`
	Cur  int       `json:"cur"`
	I    int       `json:"i"`
}

func FFArgs(src, enc string, fps int, br string) []string {
	a := []string{"-hide_banner", "-loglevel", "warning"}
	if src == "test" {
		a = append(a, "-re", "-f", "lavfi", "-i", fmt.Sprintf("testsrc2=size=1280x720:rate=%d", fps))
	} else if in, ok := strings.CutPrefix(src, "x11:"); ok { // Linux X11, с курсором: "x11::0" или "x11:WxH@:0+X,Y"
		a = append(a, "-f", "x11grab", "-framerate", strconv.Itoa(fps), "-draw_mouse", "1")
		if size, disp, ok := strings.Cut(in, "@"); ok {
			a = append(a, "-video_size", size)
			in = disp
		}
		a = append(a, "-i", in)
	} else { // Windows 8+, ffmpeg ≥ 6.0, курсор рисуется: "desktop" или "desktop:N" (N — выход DXGI)
		out := 0
		if n, ok := strings.CutPrefix(src, "desktop:"); ok {
			out, _ = strconv.Atoi(n)
		}
		a = append(a, "-f", "lavfi", "-i", fmt.Sprintf("ddagrab=output_idx=%d:framerate=%d", out, fps), "-vf", "hwdownload,format=bgra")
	}
	// ponytail: GOP = 1 с вместо реакции на PLI — потеря кадра лечится ≤ 1 с; PLI → когда упрёмся
	a = append(a, "-c:v", enc, "-b:v", br, "-maxrate", br, "-bufsize", br, "-g", strconv.Itoa(fps), "-bf", "0", "-pix_fmt", "yuv420p")
	if enc == "libx264" { // один слайс на кадр — длительность сэмпла ставится на слайс
		a = append(a, "-preset", "ultrafast", "-tune", "zerolatency", "-profile:v", "baseline", "-x264-params", "sliced-threads=0")
	}
	return append(a, "-flush_packets", "1", "-f", "h264", "-")
}

// Run держит регистрацию на сервере, переподключаясь каждые 5 с до отмены ctx.
func (a *Agent) Run(ctx context.Context) {
	for ctx.Err() == nil {
		err := a.run(ctx)
		a.setOnline(false)
		log.Printf("сигнализация: %v — повтор через 5 с", err)
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
	a.Disconnect()
}

// Disconnect разрывает текущую сессию (кнопка «Разорвать» на хосте).
func (a *Agent) Disconnect() {
	a.mu.Lock()
	s, c := a.sess, a.conn
	a.mu.Unlock()
	if s == nil {
		return
	}
	if c != nil {
		a.send(context.Background(), c, "bye", s.cid, "host")
	}
	s.pc.Close()
}

func (a *Agent) setOnline(on bool) {
	a.mu.Lock()
	a.online = on
	a.mu.Unlock()
	a.notify()
}

func (a *Agent) notify() {
	a.mu.Lock()
	on, cid := a.online, ""
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

func (a *Agent) run(ctx context.Context) error {
	pub := base64.RawURLEncoding.EncodeToString(a.Key.Public().(ed25519.PublicKey))
	c, _, err := websocket.Dial(ctx, a.Server+"?host="+a.ID+"&key="+pub, nil)
	if err != nil {
		return err
	}
	defer c.CloseNow()
	c.SetReadLimit(64 << 10)
	a.mu.Lock()
	a.conn = c
	a.mu.Unlock()
	for {
		var m hub.Msg
		if err := wsjson.Read(ctx, c, &m); err != nil {
			return err
		}
		a.mu.Lock()
		s := a.sess
		a.mu.Unlock()
		switch m.Type {
		case "challenge": // REQ-F-01: доказать серверу владение ключом, за которым закреплён ID
			var nonce string
			json.Unmarshal(m.Data, &nonce)
			d, _ := json.Marshal(map[string][]byte{"sig": ed25519.Sign(a.Key, pake.RegisterMsg(a.ID, nonce))})
			wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			wsjson.Write(wctx, c, hub.Msg{V: 1, Type: "register", Data: d})
			cancel()
		case "hello":
			var d struct{ ICE []webrtc.ICEServer }
			json.Unmarshal(m.Data, &d)
			a.mu.Lock()
			a.ice = d.ICE
			a.mu.Unlock()
			log.Printf("зарегистрирован как %s, ICE-серверов: %d", a.ID, len(d.ICE))
			a.setOnline(true)
		case "error":
			log.Printf("сервер: %s", m.Data)
			switch string(m.Data) {
			case `"id_taken"`:
				return errors.New("ID занят: в сети другой экземпляр или ID закреплён за другим ключом")
			case `"bad_sig"`:
				return errors.New("сервер не принял подпись ключа хоста")
			}
		case "connect":
			a.onConnect(ctx, c, m)
		case "answer", "ice", "bye":
			if s == nil || s.cid != m.From {
				continue
			}
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
				a.mu.Lock() // свободен сразу: колбэк pion о закрытии асинхронный, а следующий connect уже в пути
				if a.sess == s {
					a.sess = nil
				}
				a.mu.Unlock()
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
func (a *Agent) onConnect(ctx context.Context, c *websocket.Conn, m hub.Msg) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case time.Now().Before(a.lockUntil):
		a.send(ctx, c, "error", m.From, "locked")
		return
	case a.sess != nil:
		a.send(ctx, c, "error", m.From, "busy")
		return
	}
	if _, secret := a.Secret(); len(secret) == 0 {
		a.send(ctx, c, "error", m.From, "nopass")
		return
	}
	s, err := a.newSession(ctx, c, m.From)
	if err != nil {
		log.Printf("сессия: %v", err)
		a.send(ctx, c, "error", m.From, "internal")
		return
	}
	a.sess = s
}

// authResult учитывает попытку входа для блокировки перебора.
func (a *Agent) authResult(cid string, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
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

func (a *Agent) newSession(ctx context.Context, c *websocket.Conn, cid string) (*session, error) {
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{ICEServers: a.ice})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*session, error) { pc.Close(); return nil, err }
	track, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{
		MimeType: webrtc.MimeTypeH264, ClockRate: 90000,
		SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
	}, "video", "anypc")
	if err != nil {
		return fail(err)
	}
	sender, err := pc.AddTrack(track)
	if err != nil {
		return fail(err)
	}
	s := &session{cid: cid, pc: pc, mons: listMonitors()}
	if a.Capture != nil && a.Bitrate > 0 {
		s.rate = rate{max: a.Bitrate, cur: a.Bitrate}
	}
	go func() { // RTCP нужно вычитывать, иначе не работают интерсепторы; отчёты о потерях — битрейту
		for {
			pkts, _, err := sender.ReadRTCP()
			if err != nil {
				return
			}
			s.onRTCP(pkts)
		}
	}()
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
		if !s.authed.Load() {
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
		case m.T == "clip" && s.clip.fromRemote(m.Text):
			if err := SetClipText(m.Text); err != nil {
				log.Printf("буфер обмена: %v", err)
			}
		case m.T == "monitor":
			if s.selectMonitor(m.I) {
				log.Printf("сессия %s: монитор %d", s.cid, m.I+1)
			}
		case m.T == "pick" && s.picking.CompareAndSwap(false, true): // одно окно выбора за раз
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
	ctl.OnOpen(func() {
		go s.watchClip(sctx, ctl)
		s.mu.Lock()
		b, _ := json.Marshal(ctlMsg{T: "monitors", List: s.mons, Cur: s.mon})
		s.mu.Unlock()
		ctl.SendText(string(b))
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) { // каналы от клиента — только файлы и только после входа
		if dc.Label() == "file" && s.authed.Load() {
			a.receiveFile(dc)
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
				a.mu.Lock()
				if a.sess == s {
					a.sess = nil
				}
				a.mu.Unlock()
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
	a.send(ctx, c, "offer", cid, offer)
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
		conf, err := pake.HostFinish(cur, m.Msg, m.Conf)
		a.authResult(s.cid, err == nil)
		reject := func(t string) {
			send(authMsg{T: t})
			a.mu.Lock() // освободить сразу: повтор не должен получить «занят»
			if a.sess == s {
				a.sess = nil
			}
			a.mu.Unlock()
			time.AfterFunc(500*time.Millisecond, func() { s.pc.Close() }) // дать дойти ответу
		}
		if err != nil {
			reject("fail")
			return
		}
		if a.Confirm == nil {
			a.accept(ctx, s, track, send, conf, fpc, fph)
			return
		}
		// REQ-F-03: пароль верный — теперь спросить человека на хосте (до 30 с; ответ не держит канал)
		s.asking.Store(true)
		send(authMsg{T: "ask"})
		go func() {
			s.mu.Lock()
			peer := s.peer
			s.mu.Unlock()
			ok := a.Confirm(s.cid, peer)
			s.asking.Store(false)
			switch {
			case ctx.Err() != nil: // клиент ушёл, пока ждали ответа
			case ok:
				a.accept(ctx, s, track, send, conf, fpc, fph)
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
func (a *Agent) accept(ctx context.Context, s *session, track *webrtc.TrackLocalStaticSample, send func(authMsg), conf []byte, fpc, fph string) {
	s.authed.Store(true)
	send(authMsg{T: "ok", Conf: conf, Pub: a.Key.Public().(ed25519.PublicKey), Sig: pake.HostSign(a.Key, a.ID, fpc, fph)})
	log.Printf("сессия %s: вход выполнен", s.cid)
	closeInd, err := showIndicator(s.cid, a.Disconnect) // REQ-F-15
	if err != nil {                                     // REQ-S-08: без видимой плашки сессии нет
		log.Printf("плашка сессии: %v — сессия закрыта", err)
		s.pc.Close()
		return
	}
	s.mu.Lock()
	s.closeInd = closeInd
	s.mu.Unlock()
	a.notify()
	go a.stream(ctx, s, track)
}

// watchClip отправляет клиенту изменения буфера обмена хоста (только изменения после начала сессии).
func (s *session) watchClip(ctx context.Context, ctl *webrtc.DataChannel) {
	seq := ClipSeq()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if n := ClipSeq(); n != seq {
			seq = n
			if text, err := ClipText(); err == nil && s.clip.toRemote(text) {
				b, _ := json.Marshal(ctlMsg{T: "clip", Text: text})
				ctl.SendText(string(b))
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

// streamOnce: ffmpeg пишет H.264 Annex-B в stdout, NAL-юниты уходят в трек.
// ponytail: h264reader отдаёт NAL только по старт-коду следующего → +1 кадр задержки (33 мс при 30 к/с);
// убрать — читать пакеты из контейнера (nut/mkv) или кодировать в процессе.
func (a *Agent) streamOnce(ctx context.Context, s *session, track *webrtc.TrackLocalStaticSample) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.mu.Lock()
	s.capCancel = cancel
	mon, kbps := s.mon, s.rate.cur
	s.mu.Unlock()
	var cmd *exec.Cmd
	if a.Capture != nil {
		var err error
		if cmd, err = a.Capture(ctx, mon, kbps); err != nil {
			log.Printf("захват: %v", err)
			return
		}
	} else {
		bin := a.FFmpeg
		if bin == "" {
			bin = "ffmpeg"
		}
		cmd = exec.CommandContext(ctx, bin, a.FF...)
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
	defer cmd.Wait()
	r, err := h264reader.NewReader(out)
	if err != nil {
		log.Printf("h264: %v", err)
		return
	}
	frame := time.Second / time.Duration(a.FPS)
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
