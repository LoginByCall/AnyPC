package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/hub"
	"anypc/pake"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/pion/webrtc/v4"
)

var salt = []byte("0123456789abcdef")

func newAgent(url, id string, ff []string) *Agent {
	secret := pake.KDF("secret123", salt)
	_, key, _ := ed25519.GenerateKey(nil)
	return &Agent{Server: url, ID: id, Secret: func() ([]byte, []byte) { return salt, secret }, Key: key, FF: ff, FPS: 30}
}

func local(t *testing.T) string {
	srv := httptest.NewServer(&hub.Hub{})
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

// TestE2E: сигнализация + пароль + ICE + DTLS + ffmpeg (testsrc) → видео H.264 и канал ввода; bye закрывает сессию.
func TestE2E(t *testing.T) {
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", 30, "1M"), "secret123")
}

// TestWrongPassword: CPace с неверным паролем → отказ, видео не идёт (REQ-S-02).
func TestWrongPassword(t *testing.T) {
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", 30, "1M"), "wrong-pass")
}

// TestCaptureRestart — регрессия 887a0026: ffmpeg завершается через 0,5 с, видео должно идти дальше.
func TestCaptureRestart(t *testing.T) {
	ff := FFArgs("test", "libx264", 30, "1M")
	ff = append(ff[:len(ff)-3:len(ff)-3], "-t", "0.5", "-f", "h264", "-")
	e2e(t, local(t), "123456789", false, ff, "secret123")
}

// TestLive: то же через боевой сервер, только TURN. ANYPC_LIVE=wss://hk.anypc.org/ws,wss://ru.anypc.org/ws
func TestLive(t *testing.T) {
	url := os.Getenv("ANYPC_LIVE")
	if url == "" {
		t.Skip("ANYPC_LIVE не задан")
	}
	e2e(t, url, hub.RandDigits(9), true, FFArgs("test", "libx264", 30, "1M"), "secret123")
}

func e2e(t *testing.T, url, id string, relay bool, ff []string, pass string) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("нет ffmpeg")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sessions := make(chan string, 10)
	var asked, denied, gotOK, gotMons atomic.Bool
	defer func() { // каналы ctl и auth не упорядочены между собой — проверяем итог: без входа списка нет
		if !gotOK.Load() && gotMons.Load() {
			t.Error("список мониторов ушёл без входа")
		}
	}()
	a := newAgent(url, id, ff)
	if e2eAgent != nil {
		e2eAgent(a)
	}
	a.OnState = func(_ bool, s string) { sessions <- s }
	go a.Run(ctx)

	c, _, err := websocket.Dial(ctx, url[strings.LastIndex(url, ",")+1:], nil) // клиент — через последний хаб списка хоста
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	read := func() hub.Msg {
		var m hub.Msg
		if err := wsjson.Read(ctx, c, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	send := func(typ string, v any) {
		d, _ := json.Marshal(v)
		wsjson.Write(ctx, c, hub.Msg{V: 1, Type: typ, To: id, Data: d})
	}
	var hello struct{ ICE []webrtc.ICEServer }
	json.Unmarshal(read().Data, &hello)
	if e2eSquat > 0 {
		sctx, stop := context.WithCancel(ctx)
		defer stop()
		var wg sync.WaitGroup
		for range e2eSquat {
			wg.Go(func() { squat(t, sctx, url[strings.LastIndex(url, ",")+1:], id) })
		}
		time.Sleep(2 * time.Second) // молчуны получили offer раньше настоящего клиента
		defer wg.Wait()
		defer stop()
	}

	var m hub.Msg
	for { // пароль в connect больше не передаётся; ждём регистрации хоста
		var cr connectReq
		if e2eKey != "" {
			k, _ := pake.ClientSignB64(e2eSeed(), id, "", "")
			cr.CPub, _ = base64.StdEncoding.DecodeString(k["pub"])
		}
		send("connect", cr)
		if m = read(); m.Type == "offer" {
			break
		}
		if string(m.Data) != `"not_found"` {
			t.Fatalf("ждали offer: %+v", m)
		}
		time.Sleep(100 * time.Millisecond)
	}
	cfg := webrtc.Configuration{ICEServers: hello.ICE}
	if relay {
		cfg.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	pc, _ := webrtc.NewPeerConnection(cfg)
	defer pc.Close()
	got := make(chan string, 1)
	authed := make(chan bool, 1)
	dcOpen := make(chan *webrtc.DataChannel, 1)
	ctlOpen := make(chan *webrtc.DataChannel, 1)
	ctlMsgs := make(chan ctlMsg, 8)
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		switch dc.Label() {
		case "ctl":
			dc.OnOpen(func() { ctlOpen <- dc })
			dc.OnMessage(func(m webrtc.DataChannelMessage) {
				var cm ctlMsg
				if json.Unmarshal(m.Data, &cm) == nil {
					if cm.T == "monitors" {
						gotMons.Store(true)
					}
					ctlMsgs <- cm
				}
			})
		case "input":
			dc.OnOpen(func() { dcOpen <- dc })
		case "auth": // как клиент в ui/index.html + app: CPace с отпечатками из своих SDP
			var wantConf []byte
			dc.OnMessage(func(msg webrtc.DataChannelMessage) {
				if !msg.IsString { // браузер ждёт JSON строкой (регрессия: ArrayBuffer ломал вход в веб-клиенте)
					t.Error("сообщение auth не текстовое")
				}
				var am authMsg
				json.Unmarshal(msg.Data, &am)
				switch am.T {
				case "a":
					b, conf, hc, err := pake.ClientRespond(pass, am.Salt, am.Msg, id,
						pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP))
					if err != nil {
						t.Error(err)
						return
					}
					wantConf = hc
					bm := authMsg{T: "b", Msg: b, Conf: conf}
					if e2eKey != "" {
						k, _ := pake.ClientSignB64(e2eSeed(), id, pc.LocalDescription().SDP, pc.RemoteDescription().SDP)
						bm.CPub, _ = base64.StdEncoding.DecodeString(k["pub"])
						bm.CSig, _ = base64.StdEncoding.DecodeString(k["sig"])
						if e2eKey == "bad" {
							bm.CSig[0] ^= 1
						}
					}
					out, _ := json.Marshal(bm)
					dc.Send(out)
				case "ok": // ключ подтверждён CPace, личность хоста — подписью над DTLS-отпечатками (REQ-S-05)
					sigOK := pake.HostVerify(am.Pub, am.Sig, id, pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP)) == nil
					if !sigOK {
						t.Error("подпись хоста не прошла проверку")
					}
					gotOK.Store(true)
					authed <- bytes.Equal(am.Conf, wantConf) && sigOK
				case "ask":
					asked.Store(true)
				case "fail", "denied", "locked":
					denied.Store(am.T == "denied")
					authed <- false
				}
			})
		}
	})
	pc.OnTrack(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		t0 := time.Now()
		for i := 0; i < 300; i++ {
			if _, _, err := tr.ReadRTP(); err != nil {
				return
			}
		}
		t.Logf("300 RTP за %v", time.Since(t0))
		got <- tr.Codec().MimeType
	})
	pc.OnICECandidate(func(ci *webrtc.ICECandidate) {
		if ci != nil {
			send("ice", ci.ToJSON())
		}
	})
	var offer webrtc.SessionDescription
	json.Unmarshal(m.Data, &offer)
	pc.SetRemoteDescription(offer)
	ans, _ := pc.CreateAnswer(nil)
	pc.SetLocalDescription(ans)
	send("answer", ans)
	go func() {
		for {
			var m hub.Msg
			if wsjson.Read(ctx, c, &m) != nil {
				return
			}
			if m.Type == "ice" {
				var ci webrtc.ICECandidateInit
				json.Unmarshal(m.Data, &ci)
				pc.AddICECandidate(ci)
			}
		}
	}()
	var ok bool
	select {
	case ok = <-authed:
	case <-ctx.Done():
		t.Fatal("вход не завершился за 20 с")
	}
	if pass != "secret123" || e2eDeny || e2eKey == "bad" { // ошибочный путь: отказ и никакого видео
		if ok {
			t.Fatal("неверный пароль принят или отказ на хосте не сработал")
		}
		if e2eDeny && (!asked.Load() || !denied.Load()) {
			t.Fatalf("отказ на хосте: ask=%v denied=%v", asked.Load(), denied.Load())
		}
		select {
		case <-got:
			t.Fatal("видео без входа")
		case <-time.After(time.Second):
		}
		return
	}
	if !ok {
		t.Fatal("верный пароль отвергнут или хост не подтвердил ключ")
	}
	select {
	case mt := <-got:
		if mt != webrtc.MimeTypeH264 {
			t.Fatalf("кодек %s", mt)
		}
	case <-ctx.Done():
		t.Fatal("нет видео за 20 с")
	}
	select {
	case dc := <-dcOpen:
		if err := dc.SendText(`{"t":"k","c":"ControlLeft","d":true}`); err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("канал input не открылся")
	}
	if e2eCtl != nil {
		select {
		case c := <-ctlOpen:
			e2eCtl(t, c, ctlMsgs)
		case <-ctx.Done():
			t.Fatal("канал ctl не открылся")
		}
	}
	if relay {
		if p, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair(); err == nil && p != nil {
			t.Logf("путь клиента: %s → %s", p.Local.Typ, p.Remote.Typ)
			if p.Local.Typ != webrtc.ICECandidateTypeRelay {
				t.Fatalf("ожидали relay, получили %s", p.Local.Typ)
			}
		}
	}
	// bye от клиента → хост освобождается сразу, без 30-секундного тайм-аута ICE
	time.Sleep(200 * time.Millisecond) // дать дойти нажатию
	send("bye", "client")
	for {
		select {
		case s := <-sessions:
			a.mu.Lock()
			free := a.sess == nil
			a.mu.Unlock()
			if s == "" && free {
				return
			}
		case <-ctx.Done():
			t.Fatal("сессия не закрылась по bye")
		}
	}
}

func TestLockout(t *testing.T) { // REQ-S-04: 5 неудачных входов → новые подключения отклоняются
	ctx := context.Background()
	c, _, _ := websocket.Dial(ctx, local(t), nil)
	defer c.CloseNow()
	a := newAgent("", "", nil)
	for i := 0; i < 5; i++ {
		a.authResult("c1", false)
	}
	a.onConnect(ctx, c, hub.Msg{From: "c000000000001"})
	if a.sess != nil || len(a.pend) > 0 || time.Until(a.lockUntil) < 50*time.Second {
		t.Fatalf("блокировка не сработала: sess=%v lock=%v", a.sess, a.lockUntil)
	}
}

func TestDecode(t *testing.T) {
	ok := map[string]event{
		`{"t":"m","x":65535,"y":0}`:           {x: 65535, y: 0, flags: mMove | mAbs},
		`{"t":"b","b":0,"d":true}`:            {flags: mLeftDown},
		`{"t":"b","b":2,"d":false}`:           {flags: mRightUp},
		`{"t":"w","v":-120}`:                  {data: -120, flags: mWheel},
		`{"t":"h","v":99999}`:                 {data: 1200, flags: mHWheel},
		`{"t":"k","c":"KeyA","d":true}`:       {key: true, scan: 0x1E, flags: kScancode},
		`{"t":"k","c":"ArrowLeft","d":false}`: {key: true, scan: 0x4B, flags: kScancode | kExtended | kUp},
		`{"t":"k","c":"MetaLeft","d":true}`:   {key: true, scan: 0x5B, flags: kScancode | kExtended},
	}
	for in, want := range ok {
		if got, err := decode([]byte(in)); err != nil || got != want {
			t.Errorf("%s → %+v, %v; ждали %+v", in, got, err, want)
		}
	}
	for _, in := range []string{`{"t":"m","x":-1,"y":0}`, `{"t":"m","x":0,"y":70000}`, `{"t":"b","b":3}`,
		`{"t":"k","c":"Fn"}`, `{"t":"zz"}`, `not json`} {
		if _, err := decode([]byte(in)); err == nil {
			t.Errorf("%s: ждали ошибку", in)
		}
	}
}

func TestRelease(t *testing.T) { // при разрыве отпускается всё зажатое, и только оно
	var h held
	for _, in := range []string{`{"t":"k","c":"ControlLeft","d":true}`, `{"t":"k","c":"AltRight","d":true}`,
		`{"t":"k","c":"KeyA","d":true}`, `{"t":"k","c":"KeyA","d":false}`, `{"t":"b","b":0,"d":true}`} {
		e, _ := decode([]byte(in))
		h.track(e)
	}
	rel := h.release()
	if len(rel) != 3 {
		t.Fatalf("ждали 3 отпускания (Ctrl, AltGr, ЛКМ): %+v", rel)
	}
	for _, e := range rel {
		if e.key && (e.flags&kUp == 0 || (e.scan == 0x38) != (e.flags&kExtended != 0)) {
			t.Errorf("неверное отпускание клавиши %+v", e)
		}
		if !e.key && e.flags != mLeftUp {
			t.Errorf("неверное отпускание кнопки %+v", e)
		}
	}
	if len(h.release()) != 0 {
		t.Error("повторный release не пуст")
	}
}

func TestClipEcho(t *testing.T) {
	var c clipSync
	if !c.fromRemote("из клиента") || c.toRemote("из клиента") {
		t.Fatal("текст от клиента вернулся эхом")
	}
	if !c.toRemote("локальный") || c.toRemote("локальный") {
		t.Fatal("локальное изменение: отправить один раз")
	}
	big := strings.Repeat("я", ClipMax) // 2 байта на символ — больше предела
	if c.toRemote("") || c.toRemote(big) || c.fromRemote(big) {
		t.Fatal("пустой или слишком большой текст принят")
	}
}

// Крючки e2e для отдельных тестов (по умолчанию nil).
var (
	e2eAgent func(*Agent)
	e2eDeny  bool // ожидать отказ человека на хосте (REQ-F-03)
	e2eCtl   func(*testing.T, *webrtc.DataChannel, chan ctlMsg)
	e2eSquat int    // столько клиентов до настоящего шлют connect и молчат (У3, У9)
	e2eKey   string // seed ключа клиента (base64): заявить в connect и подписать в «b» (У3); "bad" — заявить, подпись испортить
)

// squat — клиент, который получил offer и не отвечает: раньше одного такого хватало, чтобы хост 20 с был «занят».
func squat(t *testing.T, ctx context.Context, url, id string) {
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Error(err)
		return
	}
	var m hub.Msg
	wsjson.Read(ctx, c, &m) // hello
	for ctx.Err() == nil {
		wsjson.Write(ctx, c, hub.Msg{V: 1, Type: "connect", To: id, Data: json.RawMessage(`{}`)})
		if wsjson.Read(ctx, c, &m) != nil || m.Type == "offer" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	<-ctx.Done()
	c.CloseNow()
}

// e2eSeed — постоянный seed ключа клиента для тестов У3.
func e2eSeed() string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) }

// TestTrustedLocked — У3: при блокировке перебора владелец с закреплённым ключом входит (с паролем);
// заявка того же ключа без верной подписи — отказ, и не считается.
func TestTrustedLocked(t *testing.T) {
	k, _ := pake.ClientSignB64(e2eSeed(), "", "", "")
	pub, _ := base64.StdEncoding.DecodeString(k["pub"])
	var trusted atomic.Bool
	e2eAgent = func(a *Agent) {
		a.fails, a.lockUntil = 9, time.Now().Add(time.Hour)
		a.Trusted = func(p []byte) bool { return trusted.Load() && bytes.Equal(p, pub) }
		a.Trust = func(p []byte) { trusted.Store(bytes.Equal(p, pub)) }
	}
	defer func() { e2eAgent, e2eKey = nil, "" }()
	trusted.Store(true)
	e2eKey = "ok"
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", 30, "1M"), "secret123")
	e2eKey = "bad"
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", 30, "1M"), "secret123")
}

// TestTrustEnroll — верный пароль с подписью ключа закрепляет ключ; неверный — нет.
func TestTrustEnroll(t *testing.T) {
	var got atomic.Bool
	e2eAgent = func(a *Agent) { a.Trust = func([]byte) { got.Store(true) } }
	defer func() { e2eAgent, e2eKey = nil, "" }()
	e2eKey = "ok"
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", 30, "1M"), "wrong-pass")
	if got.Load() {
		t.Fatal("ключ закреплён при неверном пароле")
	}
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", 30, "1M"), "secret123")
	if !got.Load() {
		t.Fatal("ключ не закреплён после входа")
	}
}

// TestPendingSquat — молчащие клиенты (меньше maxPending) не мешают войти владельцу.
func TestPendingSquat(t *testing.T) {
	e2eSquat = 2 // < maxPending
	defer func() { e2eSquat = 0 }()
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", 30, "1M"), "secret123")
}

// TestMonitorSwitch — REQ-F-09: хост присылает список мониторов, выбор второго перезапускает захват на нём.
func TestMonitorSwitch(t *testing.T) {
	two := []Monitor{{Name: "A", W: 1920, H: 1080, Primary: true}, {Name: "B", X: 1920, W: 1280, H: 720}}
	listMonitors = func() []Monitor { return two }
	calls := make(chan int, 10)
	e2eAgent = func(a *Agent) {
		a.Capture = func(ctx context.Context, mon, _, _ int) (*exec.Cmd, error) {
			calls <- mon
			return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", 30, "1M")...), nil
		}
	}
	e2eCtl = func(t *testing.T, ctl *webrtc.DataChannel, msgs chan ctlMsg) {
		select {
		case m := <-msgs:
			if m.T != "monitors" || len(m.List) != 2 || m.Cur != 0 {
				t.Fatalf("список мониторов: %+v", m)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("нет списка мониторов")
		}
		if first := <-calls; first != 0 {
			t.Fatalf("первый захват монитора %d, ждали основной 0", first)
		}
		ctl.SendText(`{"t":"monitor","i":1}`)
		select {
		case mon := <-calls:
			if mon != 1 {
				t.Fatalf("после выбора захват монитора %d", mon)
			}
		case <-time.After(2 * time.Second): // REQ-F-09: ≤ 1 с; с запасом на тест
			t.Fatal("захват не перезапустился на втором мониторе")
		}
	}
	defer func() { listMonitors, e2eAgent, e2eCtl = monitors, nil, nil }()
	e2e(t, local(t), "123456789", false, nil, "secret123")
}

func TestMonitorHelpers(t *testing.T) {
	m := &Monitor{X: 1920, Y: -200, W: 1280, H: 720}
	if x, y := monPoint(m, 0, 65535); x != 1920 || y != 519 {
		t.Errorf("monPoint: %d,%d", x, y)
	}
	join := func(a []string) string { return strings.Join(a, " ") }
	if a := join(FFArgs("desktop:2", "libx264", 30, "1M")); !strings.Contains(a, "ddagrab=output_idx=2:framerate=30") {
		t.Errorf("ddagrab: %s", a)
	}
	if a := join(FFArgs("x11:1280x720@:0+1920,0", "libx264", 30, "1M")); !strings.Contains(a, "-video_size 1280x720 -i :0+1920,0") {
		t.Errorf("x11grab: %s", a)
	}
	cancelled := false
	s := &session{mons: []Monitor{{}, {}}, capCancel: func() { cancelled = true }}
	if !s.selectMonitor(1) || !cancelled || s.mon != 1 || !s.switched.Load() {
		t.Error("переключение на 1")
	}
	if s.selectMonitor(1) || s.selectMonitor(5) || s.selectMonitor(-1) {
		t.Error("тот же или несуществующий монитор принят")
	}
}

// TestConfirm — REQ-F-03: после верного пароля хост спрашивает человека; «Отклонить» → отказ без видео,
// хост свободен; «Разрешить» → обычная сессия. Окно получает ID клиента и его адрес.
func TestConfirm(t *testing.T) {
	var gotPeer atomic.Value
	answer := false
	e2eAgent = func(a *Agent) {
		a.Confirm = func(cid, peer string) bool { gotPeer.Store(cid + "|" + peer); return answer }
	}
	defer func() { e2eAgent, e2eDeny = nil, false }()
	e2eDeny = true
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", 30, "1M"), "secret123")
	if p, _ := gotPeer.Load().(string); !strings.HasPrefix(p, "c") || strings.HasSuffix(p, "|") {
		t.Fatalf("окну не передан клиент и адрес: %q", p)
	}
	answer, e2eDeny = true, false
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", 30, "1M"), "secret123")
}

// TestDeadProxy — регрессия: мёртвый прокси из окружения (HTTPS_PROXY на закрытый порт) не мешает
// подключиться к сигнализации напрямую; живой прокси по-прежнему используется.
func TestDeadProxy(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + l.Addr().String()
	l.Close() // порт закрыт — как 127.0.0.1:12334
	used := false
	defer func(p func(*http.Request) (*url.URL, error)) { proxy = p }(proxy)
	proxy = func(*http.Request) (*url.URL, error) { used = true; return url.Parse(dead) }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dial(ctx, local(t))
	if err != nil || !used {
		t.Fatalf("напрямую после мёртвого прокси: err=%v, прокси пробовали=%v", err, used)
	}
	c.CloseNow()
}

// TestTwoHubs — резервная сигнализация: хост в сети на двух хабах сразу, клиент входит через второй
// (первый мог бы быть недоступен из его сети); видео, ввод и вход по паролю — как через один хаб.
func TestTwoHubs(t *testing.T) {
	e2e(t, local(t)+","+local(t), "123456789", false, FFArgs("test", "libx264", 30, "1M"), "secret123")
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "ws://" + l.Addr().String() + "/ws"
	l.Close() // недоступный хаб не мешает живому
	e2e(t, dead+","+local(t), "123456789", false, FFArgs("test", "libx264", 30, "1M"), "secret123")
}

// TestHubSpoof — Д-4: хаб пересылает сообщения с From отправителя. Поддельные error id_taken (выкидывал хост
// из сети) и hello (подменял TURN) от постороннего агент должен пропускать мимо.
func TestHubSpoof(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conns.Add(1)
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		ctx := r.Context()
		nonce, _ := json.Marshal("n")
		wsjson.Write(ctx, c, hub.Msg{V: 1, Type: "challenge", Data: nonce})
		var reg hub.Msg
		wsjson.Read(ctx, c, &reg)
		wsjson.Write(ctx, c, hub.Msg{V: 1, Type: "hello", Data: json.RawMessage(`{"id":"123456789","ice":[{"urls":["stun:good.example:3478"]}]}`)})
		wsjson.Write(ctx, c, hub.Msg{V: 1, Type: "hello", From: "c1", Data: json.RawMessage(`{"ice":[{"urls":["turn:evil.example:3478"]}]}`)})
		wsjson.Write(ctx, c, hub.Msg{V: 1, Type: "error", From: "c1", Data: json.RawMessage(`"id_taken"`)})
		<-ctx.Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a := newAgent("ws"+strings.TrimPrefix(srv.URL, "http"), "123456789", nil)
	go a.Run(ctx)
	time.Sleep(1500 * time.Millisecond)
	a.mu.Lock()
	ice, on := a.ice, len(a.online)
	a.mu.Unlock()
	if len(ice) != 1 || ice[0].URLs[0] != "stun:good.example:3478" {
		t.Errorf("ICE подменён посторонним: %+v", ice)
	}
	if n := conns.Load(); n != 1 || on != 1 {
		t.Errorf("поддельный id_taken разорвал связь с хабом: подключений %d, в сети %d", n, on)
	}
}

// TestClipBeforeAuth — Д-5: буфер хоста уходил в канал ctl до ввода пароля (20 с ожидания входа).
func TestClipBeforeAuth(t *testing.T) {
	var seq atomic.Uint32
	defer func(a func() uint32, b func() (string, error)) { clipSeq, clipText = a, b }(clipSeq, clipText)
	clipSeq, clipText = func() uint32 { return seq.Load() }, func() (string, error) { return "пароль от банка", nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sent := make(chan string, 4)
	s := &session{}
	go s.watchClip(ctx, func(b []byte) { sent <- string(b) })
	time.Sleep(100 * time.Millisecond)
	seq.Add(1) // буфер изменился, входа нет
	select {
	case m := <-sent:
		t.Fatalf("до входа ушёл буфер: %s", m)
	case <-time.After(1200 * time.Millisecond):
	}
	s.authed.Store(true)
	seq.Add(1)
	select {
	case m := <-sent:
		if !strings.Contains(m, "пароль от банка") {
			t.Fatalf("после входа: %s", m)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("после входа изменение буфера не ушло")
	}
}
