package agent

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/hub"
	"anypc/pake"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
)

var salt = []byte("0123456789abcdef")

func newAgent(url, id string, ff []string) *Agent {
	secret := pake.KDF("secret123", salt)
	_, key, _ := ed25519.GenerateKey(nil)
	secretOf := func(u string) ([]byte, []byte, bool) { // одна запись — по умолчанию
		if u != "" {
			return nil, nil, false
		}
		return salt, secret, false
	}
	return &Agent{Server: url, ID: id, Secret: secretOf, Key: key, FF: ff, FPS: 30}
}

func local(t *testing.T) string {
	srv := httptest.NewServer(&hub.Hub{})
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

// TestE2E: сигнализация + пароль + ICE + DTLS + ffmpeg (testsrc) → видео H.264 и канал ввода; bye закрывает сессию.
func TestE2E(t *testing.T) {
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
}

// TestWrongPassword: CPace с неверным паролем → отказ, видео не идёт (REQ-S-02).
func TestWrongPassword(t *testing.T) {
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "wrong-pass")
}

// TestCaptureRestart — регрессия 887a0026: ffmpeg завершается через 0,5 с, видео должно идти дальше.
func TestCaptureRestart(t *testing.T) {
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	ff = append(ff[:len(ff)-3:len(ff)-3], "-t", "0.5", "-f", "h264", "-")
	e2e(t, local(t), "123456789", false, ff, "secret123")
}

// TestCaptureBlocked — F7: экран заблокирован → захват не запускается, клиенту state locked; после разблокировки
// список мониторов снят заново и ушёл клиенту; захват без единого кадра → пауза noFramePause и state nocapture
// (раньше перезапуск каждые 300 мс без конца); пошли кадры → state ok.
func TestCaptureBlocked(t *testing.T) {
	var unlocked atomic.Bool
	var mu sync.Mutex
	var calls []time.Time
	listMonitors = func() []Monitor { // на заблокированном Маке список пуст
		if unlocked.Load() {
			return []Monitor{{Name: "A", W: 1920, H: 1080, Primary: true}}
		}
		return nil
	}
	e2eAgent = func(a *Agent) {
		var once sync.Once
		var t0 time.Time
		a.Locked = func() bool {
			once.Do(func() { t0 = time.Now() })
			if time.Since(t0) < time.Second {
				return true
			}
			unlocked.Store(true)
			return false
		}
		a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) {
			if !unlocked.Load() {
				t.Error("захват запущен на заблокированном экране")
			}
			mu.Lock()
			calls = append(calls, time.Now())
			n := len(calls)
			mu.Unlock()
			if n <= 2 { // экран блокировки / UAC: процесс завершается, не дав ни кадра
				return exec.CommandContext(ctx, "ffmpeg", "-loglevel", "quiet", "-i", "/nonexistent/anypc"), nil
			}
			return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})...), nil
		}
	}
	e2eCtl = func(t *testing.T, _ *webrtc.DataChannel, msgs chan ctlMsg) {
		var states []string
		mons := false
		deadline := time.After(5 * time.Second)
		for !mons || !slices.Contains(states, "ok") {
			select {
			case m := <-msgs:
				switch {
				case m.T == "state":
					states = append(states, m.S)
				case m.T == "monitors" && len(m.List) == 1:
					mons = true
				}
			case <-deadline:
				t.Fatalf("состояния %v, список после разблокировки %v", states, mons)
			}
		}
		if states = slices.Compact(states); !slices.Equal(states, []string{"locked", "nocapture", "ok"}) {
			t.Errorf("состояния %v, ждали locked → nocapture → ok", states)
		}
		mu.Lock()
		c := slices.Clone(calls)
		mu.Unlock()
		if len(c) < 3 {
			t.Fatalf("запусков захвата %d", len(c))
		}
		for i := 1; i < 3; i++ {
			if d := c[i].Sub(c[i-1]); d < noFramePause-100*time.Millisecond {
				t.Errorf("повтор захвата без кадров через %v, ждали ≥ %v", d, noFramePause)
			}
		}
	}
	defer func() { listMonitors, e2eAgent, e2eCtl = monitors, nil, nil }()
	e2e(t, local(t), "123456789", false, nil, "secret123")
}

// TestStateRepeat — D3: первый state мог потеряться (пришёл на клиент раньше входа) — пока экран заблокирован,
// хост повторяет текущее состояние не чаще stateEvery.
func TestStateRepeat(t *testing.T) {
	lockPoll = 50 * time.Millisecond
	stateEvery.Store(int64(300 * time.Millisecond))
	const hold = 1500 * time.Millisecond
	e2eAgent = func(a *Agent) {
		var once sync.Once
		var t0 time.Time
		a.Locked = func() bool {
			once.Do(func() { t0 = time.Now() })
			return time.Since(t0) < hold
		}
		a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) {
			return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})...), nil
		}
	}
	e2eCtl = func(t *testing.T, _ *webrtc.DataChannel, msgs chan ctlMsg) {
		locked := 0
		for deadline := time.After(5 * time.Second); ; {
			select {
			case m := <-msgs:
				if m.T == "state" && m.S == "locked" {
					locked++
				}
				if m.T != "state" || m.S != "ok" {
					continue
				}
			case <-deadline:
				t.Fatalf("нет state ok, locked пришёл %d раз", locked)
			}
			break
		}
		if every := time.Duration(stateEvery.Load()); locked < 3 || locked > int(hold/every)+1 {
			t.Errorf("state locked за %v пришёл %d раз, ждали 3…%d (повтор раз в %v)", hold, locked, int(hold/every)+1, every)
		}
	}
	defer func() { lockPoll, e2eAgent, e2eCtl = 2*time.Second, nil, nil; stateEvery.Store(int64(2 * time.Second)) }()
	e2e(t, local(t), "123456789", false, nil, "secret123")
}

// TestMonitorsRetry — D4: список мониторов снимался один раз (после разблокировки); если дисплеи ещё не проснулись,
// он оставался пустым до конца сессии. Теперь, пока пуст, — снова перед каждым запуском захвата.
func TestMonitorsRetry(t *testing.T) {
	var n atomic.Int32
	listMonitors = func() []Monitor { // первые 3 снятия — пусто
		if n.Add(1) <= 3 {
			return nil
		}
		return []Monitor{{Name: "A", W: 1920, H: 1080, Primary: true}}
	}
	e2eAgent = func(a *Agent) {
		a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) { // захват завершается сам через 0,3 с
			ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
			ff = append(ff[:len(ff)-3:len(ff)-3], "-t", "0.3", "-f", "h264", "-")
			return exec.CommandContext(ctx, "ffmpeg", ff...), nil
		}
	}
	e2eCtl = func(t *testing.T, _ *webrtc.DataChannel, msgs chan ctlMsg) {
		for deadline := time.After(8 * time.Second); ; {
			select {
			case m := <-msgs:
				if m.T == "monitors" && len(m.List) == 1 {
					return
				}
			case <-deadline:
				t.Fatalf("список мониторов не пришёл (снятий %d)", n.Load())
			}
		}
	}
	defer func() { listMonitors, e2eAgent, e2eCtl = monitors, nil, nil }()
	e2e(t, local(t), "123456789", false, nil, "secret123")
}

// TestCaptureDenied — регрессия: «Отмена» в окне портала Wayland вызывала окно снова каждые 300 мс (потом 2 с).
// Теперь отказ человека закрывает сессию: клиент получает state "denied", захват не повторяется.
func TestCaptureDenied(t *testing.T) {
	var calls atomic.Int32
	var ag *Agent
	e2eAgent = func(a *Agent) {
		ag = a
		a.Capture = func(context.Context, Cap) (*exec.Cmd, error) {
			calls.Add(1)
			return nil, fmt.Errorf("портал: %w", ErrCaptureDenied)
		}
	}
	e2eNoVideo = true
	e2eCtl = func(t *testing.T, _ *webrtc.DataChannel, msgs chan ctlMsg) {
		deadline := time.After(5 * time.Second)
		for denied := false; !denied; {
			select {
			case m := <-msgs:
				denied = m.T == "state" && m.S == "denied"
			case <-deadline:
				t.Fatal("клиент не получил state denied")
			}
		}
		time.Sleep(noFramePause + 500*time.Millisecond) // повтор был бы здесь
		if n := calls.Load(); n != 1 {
			t.Errorf("запусков захвата %d, ждали 1 (без повторов после отказа)", n)
		}
		ag.mu.Lock()
		busy := ag.sess != nil
		ag.mu.Unlock()
		if busy {
			t.Error("сессия на хосте не закрыта после отказа")
		}
	}
	defer func() { e2eAgent, e2eCtl, e2eNoVideo = nil, nil, false }()
	e2e(t, local(t), "123456789", false, nil, "secret123")
}

// TestLive: то же через боевой сервер, только TURN. ANYPC_LIVE=wss://hk.anypc.org/ws,wss://ru.anypc.org/ws
func TestLive(t *testing.T) {
	url := os.Getenv("ANYPC_LIVE")
	if url == "" {
		t.Skip("ANYPC_LIVE не задан")
	}
	e2e(t, url, hub.RandDigits(9), true, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
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
		cr.VP9 = e2eVP9
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
	ctlMsgs := make(chan ctlMsg, 32) // до e2eCtl копятся: monitors, state (TestCaptureBlocked), cur
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
			otpN := 0
			dc.OnClose(func() { // хост закрыл сессию (не дождался кода TOTP) — вход не состоялся
				select {
				case authed <- false:
				default:
				}
			})
			dc.OnMessage(func(msg webrtc.DataChannelMessage) {
				if !msg.IsString { // браузер ждёт JSON строкой (регрессия: ArrayBuffer ломал вход в веб-клиенте)
					t.Error("сообщение auth не текстовое")
				}
				var am authMsg
				json.Unmarshal(msg.Data, &am)
				if e2eSeen != nil {
					e2eSeen(am)
				}
				switch am.T {
				case "a":
					if e2eUser != "" && am.User == "" { // как ui/index.html: запись по имени — первое "a" (по умолчанию) не для нас
						if !am.Users {
							t.Error("хост не объявил users в первом a")
						}
						out, _ := json.Marshal(authMsg{T: "a", User: e2eUser})
						dc.Send(out)
						if e2eTwice {
							dc.Send(out)
						}
						return
					}
					if am.User != e2eUser {
						t.Errorf("ответ хоста на имя %q, а не %q", am.User, e2eUser)
					}
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
				case "otp": // второй фактор: хост уже доказал пароль (conf) и ключ (подпись), как в "ok"
					if !bytes.Equal(am.Conf, wantConf) || pake.HostVerify(am.Pub, am.Sig, id, pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP)) != nil {
						t.Error("запрос кода TOTP без доказательства хоста")
					}
					otpN++
					if e2eOTP != nil {
						if code := e2eOTP(otpN); code != "" {
							out, _ := json.Marshal(authMsg{T: "otp", Code: code})
							dc.Send(out)
						}
					}
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
		if e2eTrack != nil {
			e2eTrack(t, pc, tr)
		}
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
	good := cmp.Or(e2eGood, "secret123")
	if pass != good || e2eDeny || e2eKey == "bad" || e2eFail { // ошибочный путь: отказ и никакого видео
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
	if !e2eNoVideo {
		select {
		case mt := <-got:
			if mt != e2eMime {
				t.Fatalf("кодек %s", mt)
			}
		case <-ctx.Done():
			t.Fatal("нет видео за 20 с")
		}
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
	if e2eInput != nil {
		e2eInput(t, a)
	}
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

// TestLockout — REQ-S-04, S-22: 5 неудач одного имени запирают его, а не другие имена и не хост; массовый перебор
// имён (hostLockAt по хосту) — новые подключения отклоняются; успех сбрасывает общий и свой счётчик, не чужой.
func TestLockout(t *testing.T) {
	ctx := context.Background()
	c, _, _ := websocket.Dial(ctx, local(t), nil)
	defer c.CloseNow()
	a := newAgent("", "", nil)
	for range 5 {
		a.authResult("c1", "", false)
	}
	now := time.Now()
	if f, l := nlock(a, ""); f != 5 || l < 50*time.Second || !a.pwLocked("", now) || a.pwLocked("ivan", now) || a.pwLocked("nobody", now) {
		t.Fatalf("имя: неудач %d, блокировка %v; ivan заперт %v", f, l, a.pwLocked("ivan", now))
	}
	for i := range hostLockAt - 5 { // по одной неудаче на имя — ни одно не заперто, но хост — да
		a.authResult("c1", fmt.Sprint("u", i), false)
	}
	if f, _ := nlock(a, "u0"); f != 1 || !a.pwLocked("ivan", time.Now()) {
		t.Fatalf("массовый перебор: u0 %d, ivan не заперт", f)
	}
	a.onConnect(ctx, c, hub.Msg{From: "c000000000001"})
	if a.sess != nil || len(a.pend) > 0 || time.Until(a.lockUntil) < 50*time.Second {
		t.Fatalf("блокировка не сработала: sess=%v lock=%v", a.sess, a.lockUntil)
	}
	a.authResult("c1", "ivan", true) // успех сбрасывает только счёт своего имени (приёмка Д2)
	if a.fails != hostLockAt || a.names[""] == nil || a.names["u0"] == nil {
		t.Fatalf("успех ivan сбросил общий (%d) или чужой счётчик", a.fails)
	}
	a.lockUntil, a.failAt = time.Now().Add(-2*hostForget), time.Now().Add(-3*hostForget) // час тишины после блокировки
	a.authResult("c1", "u1", false)
	if a.fails != 1 {
		t.Fatalf("общий счётчик не забылся после тишины: %d", a.fails)
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
	e2eAgent   func(*Agent)
	e2eMime    = webrtc.MimeTypeH264                                         // кодек видео, который ждёт клиент
	e2eVP9     bool                                                          // клиент просит VP9 в connect
	e2eTrack   func(*testing.T, *webrtc.PeerConnection, *webrtc.TrackRemote) // после 300 RTP видео у клиента
	e2eDeny    bool                                                          // ожидать отказ человека на хосте (REQ-F-03)
	e2eCtl     func(*testing.T, *webrtc.DataChannel, chan ctlMsg)
	e2eSquat   int                      // столько клиентов до настоящего шлют connect и молчат (У3, У9)
	e2eKey     string                   // seed ключа клиента (base64): заявить в connect и подписать в «b» (У3); "bad" — заявить, подпись испортить
	e2eNoVideo bool                     // видео не ждать (захват отклонён на хосте) — сразу к e2eCtl
	e2eOTP     func(n int) string       // код TOTP на n-й запрос хоста; "" — не отвечать
	e2eSeen    func(authMsg)            // каждое сообщение auth от хоста
	e2eFail    bool                     // ожидать отказ во входе (TOTP)
	e2eUser    string                   // имя учётной записи клиента (REQ-S-20); "" — как старый клиент: запись по умолчанию
	e2eGood    string                   // верный пароль для e2eUser; "" — secret123
	e2eTwice   bool                     // назвать имя дважды (хост обязан оборвать вход)
	e2eInput   func(*testing.T, *Agent) // после нажатия ControlLeft клиентом, до bye
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
		a.Trusted = func(p []byte, _ string) bool { return trusted.Load() && bytes.Equal(p, pub) }
		a.Trust = func(p []byte, _ string) { trusted.Store(bytes.Equal(p, pub)) }
	}
	defer func() { e2eAgent, e2eKey = nil, "" }()
	trusted.Store(true)
	e2eKey = "ok"
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
	e2eKey = "bad"
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
}

// TestTrustEnroll — верный пароль с подписью ключа закрепляет ключ; неверный — нет.
func TestTrustEnroll(t *testing.T) {
	var got atomic.Bool
	e2eAgent = func(a *Agent) { a.Trust = func([]byte, string) { got.Store(true) } }
	defer func() { e2eAgent, e2eKey = nil, "" }()
	e2eKey = "ok"
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "wrong-pass")
	if got.Load() {
		t.Fatal("ключ закреплён при неверном пароле")
	}
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
	if !got.Load() {
		t.Fatal("ключ не закреплён после входа")
	}
}

// TestPendingSquat — молчащие клиенты (меньше maxPending) не мешают войти владельцу.
func TestPendingSquat(t *testing.T) {
	e2eSquat = 2 // < maxPending
	defer func() { e2eSquat = 0 }()
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
}

// TestMonitorSwitch — REQ-F-09: хост присылает список мониторов, выбор второго перезапускает захват на нём.
func TestMonitorSwitch(t *testing.T) {
	two := []Monitor{{Name: "A", W: 1920, H: 1080, Primary: true}, {Name: "B", X: 1920, W: 1280, H: 720}}
	listMonitors = func() []Monitor { return two }
	calls := make(chan int, 10)
	e2eAgent = func(a *Agent) {
		a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) {
			calls <- c.Mon
			return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})...), nil
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

// TestPLI — потеря опорного кадра у клиента: PLI перезапускает захват (новый IDR), не раньше pliHold после старта.
func TestPLI(t *testing.T) {
	calls := make(chan time.Time, 10)
	e2eAgent = func(a *Agent) {
		a.Capture = func(ctx context.Context, _ Cap) (*exec.Cmd, error) {
			calls <- time.Now()
			return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})...), nil
		}
	}
	e2eTrack = func(t *testing.T, pc *webrtc.PeerConnection, tr *webrtc.TrackRemote) {
		first := <-calls
		pli := []rtcp.Packet{&rtcp.PictureLossIndication{MediaSSRC: uint32(tr.SSRC())}}
		if time.Since(first) < pliHold-300*time.Millisecond { // 300 RTP приходят за ~2 с — ранний PLI шлём, только если успели
			pc.WriteRTCP(pli)
		}
		select { // в любом случае дождаться pliHold: иначе второй PLI тоже «ранний» (на Маке 300 RTP за 1,7 с — тест падал)
		case <-calls:
			t.Fatal("перезапуск по PLI раньше pliHold")
		case <-time.After(time.Until(first.Add(pliHold + 100*time.Millisecond))):
		}
		pc.WriteRTCP(pli)
		select {
		case <-calls:
		case <-time.After(2 * time.Second):
			t.Fatal("захват не перезапустился по PLI")
		}
	}
	defer func() { e2eAgent, e2eTrack = nil, nil }()
	e2e(t, local(t), "123456789", false, nil, "secret123")
}

// TestQuality — клиент переключает профиль: {"t":"quality","p":"video"} перезапускает захват с Cap.Video.
func TestQuality(t *testing.T) {
	calls := make(chan Cap, 10)
	e2eAgent = func(a *Agent) {
		a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) {
			calls <- c
			return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", c)...), nil
		}
	}
	e2eCtl = func(t *testing.T, ctl *webrtc.DataChannel, _ chan ctlMsg) {
		if c := <-calls; c.Video {
			t.Fatal("первый захват — уже «видео»")
		}
		ctl.SendText(`{"t":"quality","p":"video"}`)
		select {
		case c := <-calls:
			if !c.Video {
				t.Fatalf("после переключения захват без Video: %+v", c)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("захват не перезапустился после смены профиля")
		}
		ctl.SendText(`{"t":"quality","p":"video"}`) // повтор того же — без перезапуска
		select {
		case c := <-calls:
			t.Fatalf("лишний перезапуск: %+v", c)
		case <-time.After(500 * time.Millisecond):
		}
	}
	defer func() { e2eAgent, e2eCtl = nil, nil }()
	e2e(t, local(t), "123456789", false, nil, "secret123")
}

func TestMonitorHelpers(t *testing.T) {
	m := &Monitor{X: 1920, Y: -200, W: 1280, H: 720}
	if x, y := monPoint(m, 0, 65535); x != 1920 || y != 519 {
		t.Errorf("monPoint: %d,%d", x, y)
	}
	join := func(a []string) string { return strings.Join(a, " ") }
	c := Cap{FPS: 30, Kbps: 1000, Cursor: true}
	if a := join(FFArgs("desktop:2", "libx264", c)); !strings.Contains(a, "ddagrab=output_idx=2:framerate=30:draw_mouse=1") || !strings.Contains(a, "-vf hwdownload,format=bgra ") {
		t.Errorf("ddagrab: %s", a)
	}
	if a := join(FFArgs("x11:1280x720@:0+1920,0", "libx264", c)); !strings.Contains(a, "-draw_mouse 1 -video_size 1280x720 -i :0+1920,0") {
		t.Errorf("x11grab: %s", a)
	}
	// статика не деградирует: x264 — CRF с потолком, без -b:v и периодических I-кадров; аппаратный — ABR, IDR раз в секунду
	if a := join(FFArgs("desktop", "libx264", c)); !strings.Contains(a, "-maxrate 1000k -bufsize 1000k") || !strings.Contains(a, "-crf 20") || strings.Contains(a, "-g ") || strings.Contains(a, "-b:v") || !strings.Contains(a, "keyint=infinite") {
		t.Errorf("x264: %s", a)
	}
	if a := join(FFArgs("desktop", "h264_nvenc", c)); !strings.Contains(a, "-b:v 1000k -g 30") || strings.Contains(a, "-crf") {
		t.Errorf("nvenc: %s", a)
	}
	// курсор отдельно: не рисуется в кадр; профиль «видео» ужимает до 720p только на канале < 2 Мбит/с
	sep := Cap{FPS: 30, Kbps: 1000}
	if a := join(FFArgs("desktop", "libx264", sep)); !strings.Contains(a, "draw_mouse=0") || strings.Contains(a, "scale=") {
		t.Errorf("без курсора: %s", a)
	}
	if a := join(FFArgs("avf:0", "libx264", sep)); !strings.Contains(a, "-capture_cursor 0") || !strings.Contains(a, "-vf fps=30 ") {
		t.Errorf("avf без курсора: %s", a)
	}
	if a := join(FFArgs("x11::0", "libx264", Cap{FPS: 30, Kbps: 1500, Video: true})); !strings.Contains(a, "-draw_mouse 0") || !strings.Contains(a, "-vf scale=-2:'min(720,ih)' ") {
		t.Errorf("видео 1,5 Мбит/с: %s", a)
	}
	if a := join(FFArgs("desktop", "libx264", Cap{FPS: 30, Kbps: 4000, Video: true})); strings.Contains(a, "scale=") {
		t.Errorf("видео 4 Мбит/с без масштаба: %s", a)
	}
	// vp9 (Cap.VP9): ffmpeg не кодирует — Y4M чётного размера в stdout, без параметров кодера; enc "vp9" без Cap.VP9 → libx264
	if a := join(FFArgs("desktop", "libx264", Cap{FPS: 30, Kbps: 1000, VP9: true})); !strings.HasSuffix(a, "-pix_fmt yuv420p -f yuv4mpegpipe -") || !strings.Contains(a, "trunc(iw/2)*2") || strings.Contains(a, "-c:v") || strings.Contains(a, "-crf") {
		t.Errorf("vp9: %s", a)
	}
	if a := join(FFArgs("desktop", "vp9", sep)); !strings.Contains(a, "-c:v libx264 ") || strings.Contains(a, "yuv4mpegpipe") {
		t.Errorf("enc vp9 без кодера: %s", a)
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
	answer := Deny
	e2eAgent = func(a *Agent) {
		a.Confirm = func(cid, peer string) Answer { gotPeer.Store(cid + "|" + peer); return answer }
	}
	defer func() { e2eAgent, e2eDeny = nil, false }()
	e2eDeny = true
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
	if p, _ := gotPeer.Load().(string); !strings.HasPrefix(p, "c") || strings.HasSuffix(p, "|") {
		t.Fatalf("окну не передан клиент и адрес: %q", p)
	}
	answer, e2eDeny = Allow, false
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
	answer = ViewOnly // REQ-F-20: вход и видео как обычно
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
}

// TestViewOnly — REQ-F-20: в «только просмотр» хост не принимает от клиента ни ввода, ни буфера, ни файлов;
// человек на хосте может сузить права клиента, но не расширить.
func TestViewOnly(t *testing.T) {
	s := &session{}
	if s.control() {
		t.Fatal("до входа ввод принят")
	}
	s.authed.Store(true)
	if !s.control() {
		t.Fatal("обычная сессия: ввод не принят")
	}
	s.view.Store(true)
	if s.control() {
		t.Fatal("только просмотр: ввод принят")
	}
	if l, _ := plaqueBar("ru", "c1", plaqueView); !strings.Contains(l, "только просмотр") {
		t.Errorf("плашка без пометки: %q", l)
	}
}

// TestTrustDenied — ключ клиента закрепляется только после «Разрешить»: отклонённый на хосте (REQ-F-03)
// с верным паролем не становится доверенным (иначе проходил бы блокировку).
func TestTrustDenied(t *testing.T) {
	var pinned atomic.Bool
	answer := Deny
	e2eAgent = func(a *Agent) {
		a.Confirm = func(string, string) Answer { return answer }
		a.Trust = func([]byte, string) { pinned.Store(true) }
	}
	defer func() { e2eAgent, e2eDeny, e2eKey = nil, false, "" }()
	e2eDeny, e2eKey = true, "ok"
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
	if pinned.Load() {
		t.Fatal("ключ закреплён, хотя вход отклонён на хосте")
	}
	answer, e2eDeny = Allow, false
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
	if !pinned.Load() {
		t.Fatal("ключ не закреплён после «Разрешить»")
	}
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
	e2e(t, local(t)+","+local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "ws://" + l.Addr().String() + "/ws"
	l.Close() // недоступный хаб не мешает живому
	e2e(t, dead+","+local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
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
	defer func(a func() uint32, b func() (string, error), c bool) { clipSeq, clipText = a, b; clipOnCopy.Store(c) }(clipSeq, clipText, clipOnCopy.Load())
	clipSeq, clipText = func() uint32 { return seq.Load() }, func() (string, error) { return "пароль от банка", nil }
	clipOnCopy.Store(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sent := make(chan string, 4)
	s := &session{}
	done := make(chan struct{})
	go func() { s.watchClip(ctx, func(b []byte) { sent <- string(b) }); close(done) }()
	defer func() { cancel(); <-done }() // глобалы восстанавливаются только после выхода watchClip (гонка под -race)
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

// TestClipOnCopy — Wayland (clipOnCopy): буфер хоста не опрашивается (каждый wl-paste в GNOME крадёт фокус), а
// читается только после Ctrl+C/X клиента — не больше трёх раз.
func TestClipOnCopy(t *testing.T) {
	var seq, calls atomic.Uint32
	defer func(a func() uint32, b func() (string, error), c bool) { clipSeq, clipText = a, b; clipOnCopy.Store(c) }(clipSeq, clipText, clipOnCopy.Load())
	clipSeq = func() uint32 { calls.Add(1); return seq.Load() }
	clipText = func() (string, error) { return "скопировано", nil }
	clipOnCopy.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sent := make(chan string, 4)
	s := &session{}
	s.authed.Store(true)
	done := make(chan struct{})
	go func() { s.watchClip(ctx, func(b []byte) { sent <- string(b) }); close(done) }()
	defer func() { cancel(); <-done }() // глобалы восстанавливаются только после выхода watchClip (гонка под -race)
	time.Sleep(100 * time.Millisecond)  // начальное значение прочитано
	seq.Add(1)
	select {
	case m := <-sent:
		t.Fatalf("без Ctrl+C ушёл буфер: %s", m)
	case <-time.After(1200 * time.Millisecond):
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("без Ctrl+C буфер читался %d раз (ждали 1 — при старте)", n)
	}
	var k held
	for _, e := range []event{{key: true, scan: 0x1D}, {key: true, scan: 0x2E}} { // Ctrl, C
		k.track(e)
		if k.copyKey(e) {
			s.copied.Store(true)
		}
	}
	if !s.copied.Load() {
		t.Fatal("Ctrl+C не распознан")
	}
	select {
	case m := <-sent:
		if !strings.Contains(m, "скопировано") {
			t.Fatal(m)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("после Ctrl+C буфер не ушёл")
	}
	time.Sleep(2 * time.Second)
	if n := calls.Load(); n > 4 {
		t.Fatalf("после одного Ctrl+C буфер читался %d раз", n-1)
	}
	if k.copyKey(event{key: true, scan: 0x2E, flags: kUp}) || (&held{}).copyKey(event{key: true, scan: 0x2E}) {
		t.Fatal("отпускание C или C без Ctrl приняты за копирование")
	}
}
