package agent

// Регрессии приёмки REQ-F-26 (опыты приёмщика E1–E8, 8fe46f7): Д1–Д3, Д6.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/totp"

	"github.com/pion/webrtc/v4"
)

// rawCtl — заменить обработчик ctl клиента: все сообщения как map.
func rawCtl(dc *webrtc.DataChannel) chan map[string]any {
	ch := make(chan map[string]any, 4096)
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		var v map[string]any
		if json.Unmarshal(m.Data, &v) == nil {
			ch <- v
		}
	})
	return ch
}

func waitMode(t *testing.T, ch chan map[string]any) map[string]any {
	t.Helper()
	for end := time.After(5 * time.Second); ; {
		select {
		case m := <-ch:
			if m["t"] == "mode" {
				return m
			}
		case <-end:
			t.Fatal("нет ответа mode")
			return nil
		}
	}
}

func sessOf(a *Agent) *session {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sess
}

// E1 — вход записью по имени постоянным паролем (режим «без вопросов», у записи нет TOTP → окно «Разрешить»):
// по решению владельца переключения быть не должно. Что на деле?
func TestModeAccNoOTPNamed(t *testing.T) {
	def := &otpHost{secret: totp.NewSecret()}
	us := map[string]testUser{"": {pass: "secret123", otp: def}, "olga": {pass: "olga-pass1"}}
	hosts := usersHost(us)
	var mode, view atomic.Bool
	var shown atomic.Int32
	var reply atomic.Value
	e2eAgent = func(a *Agent) {
		hosts(a)
		a.Unattended = func() bool { return true } // режим пароля: «Спрашивать» выключено
		a.Confirm = func(string, string) Answer { return ViewOnly }
		a.ConfirmControl = func(string, string) bool { shown.Add(1); return true }
	}
	e2eSeen = func(m authMsg) {
		if m.T == "ok" {
			mode.Store(m.Mode)
			view.Store(m.View)
		}
	}
	e2eCtl = func(t *testing.T, dc *webrtc.DataChannel, _ chan ctlMsg) {
		ch := rawCtl(dc)
		dc.SendText(`{"t":"mode","view":false}`)
		reply.Store(fmt.Sprint(waitMode(t, ch)))
	}
	defer func() { e2eCtl = nil; e2eReset() }()
	e2eUser, e2eGood = "olga", "olga-pass1"
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "olga-pass1")
	t.Logf("E1: запись olga, постоянный пароль, Unattended=true: ok.view=%v ok.mode=%v окон=%d ответ=%v", view.Load(), mode.Load(), shown.Load(), reply.Load())
	if mode.Load() {
		t.Errorf("E1: сессия записи по имени с постоянным паролем получила mode:true и окно смены режима")
	}
}

// E2 — приём файла идёт, сессия уходит в просмотр: следующий кусок → err, части на диске нет; новый канал — отказ;
// после возврата управления новый приём проходит.
func TestModeAccFileInFlight(t *testing.T) {
	client, host := pair(t)
	dir := t.TempDir()
	a := &Agent{FileDir: dir}
	recv := new(atomic.Int32)
	s := &session{}
	s.authed.Store(true)
	host.OnDataChannel(func(dc *webrtc.DataChannel) { a.clientChannel(s, dc, recv) })
	data := randFile(t, 1<<20)
	dc, _ := client.CreateDataChannel("file", nil)
	res := make(chan fileMsg, 8)
	dc.OnMessage(func(m webrtc.DataChannelMessage) { var fm fileMsg; json.Unmarshal(m.Data, &fm); res <- fm })
	dc.OnOpen(func() { sendJSON(dc, fileMsg{T: "meta", Name: "x.bin", Size: int64(len(data))}) })
	get := func() fileMsg {
		select {
		case r := <-res:
			return r
		case <-time.After(10 * time.Second):
			t.Fatal("нет ответа")
		}
		return fileMsg{}
	}
	if r := get(); r.T != "resume" {
		t.Fatalf("resume: %+v", r)
	}
	dc.Send(data[:fileChunk])
	time.Sleep(300 * time.Millisecond)
	if p, _ := filepath.Glob(filepath.Join(dir, ".anypc-*.part")); len(p) != 1 {
		t.Fatalf("частей %d", len(p))
	}
	s.view.Store(true) // как setMode(view): обрыв сразу, без следующего куска (Д3)
	s.dropControl()
	if r := get(); r.T != "err" || !strings.Contains(r.Msg, "только просмотр") {
		t.Errorf("E2: идущий приём не оборван: %+v", r)
	}
	time.Sleep(300 * time.Millisecond)
	left, _ := os.ReadDir(dir)
	if len(left) != 0 || recv.Load() != 0 {
		t.Errorf("E2: после обрыва в папке %d, мест %d", len(left), recv.Load())
	}
}

// E2b — новый канал в просмотре: отказ.
func TestModeAccFileNewInView(t *testing.T) {
	client, host := pair(t)
	dir := t.TempDir()
	a := &Agent{FileDir: dir}
	recv := new(atomic.Int32)
	s := &session{}
	s.authed.Store(true)
	s.view.Store(true)
	host.OnDataChannel(func(dc *webrtc.DataChannel) { a.clientChannel(s, dc, recv) })
	dc, _ := client.CreateDataChannel("file", nil)
	res := make(chan fileMsg, 8)
	dc.OnMessage(func(m webrtc.DataChannelMessage) { var fm fileMsg; json.Unmarshal(m.Data, &fm); res <- fm })
	dc.OnOpen(func() { sendJSON(dc, fileMsg{T: "meta", Name: "x.bin", Size: 10}) })
	select {
	case r := <-res:
		if r.T != "err" {
			t.Errorf("E2b: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("нет ответа")
	}
	s.view.Store(false) // повысили: новый канал принимает
	data := randFile(t, 5000)
	if r, _ := upload(t, client, "z.bin", "", data, 0, false); r.T != "done" {
		t.Errorf("E2b: после повышения приём: %+v", r)
	}
}

// E2c — очередь: файл ждёт места (maxRecv занято), сессия уходит в просмотр, место освобождается → хост открывает файл на диске?
func TestModeAccFileQueuedInView(t *testing.T) {
	client, host := pair(t)
	dir := t.TempDir()
	a := &Agent{FileDir: dir}
	recv := new(atomic.Int32)
	recv.Store(maxRecv) // все места заняты
	s := &session{}
	s.authed.Store(true)
	host.OnDataChannel(func(dc *webrtc.DataChannel) { a.clientChannel(s, dc, recv) })
	dc, _ := client.CreateDataChannel("file", nil)
	res := make(chan fileMsg, 8)
	dc.OnMessage(func(m webrtc.DataChannelMessage) { var fm fileMsg; json.Unmarshal(m.Data, &fm); res <- fm })
	dc.OnOpen(func() { sendJSON(dc, fileMsg{T: "meta", Name: "q.bin", Size: 1 << 20}) })
	time.Sleep(500 * time.Millisecond)
	s.view.Store(true)
	recv.Add(-1) // место освободилось уже в просмотре
	select {
	case r := <-res:
		p, _ := filepath.Glob(filepath.Join(dir, ".anypc-*.part"))
		t.Logf("E2c: в просмотре ждавший файл: ответ %+v, частей на диске %d, мест %d", r, len(p), recv.Load())
		if r.T != "err" || len(p) != 0 || recv.Load() != maxRecv-1 {
			t.Errorf("E2c: в «только просмотр» ждавший файл: %+v, частей %d, мест %d", r, len(p), recv.Load())
		}
	case <-time.After(3 * time.Second):
		t.Error("E2c: ответа нет")
	}
}

// E5 — спам просьбами при открытом окне и после отказа: окно одно.
func TestModeAccSpam(t *testing.T) {
	defer func(w time.Duration) { modeWait = w }(modeWait)
	modeWait = 2 * time.Second
	ctx := context.Background()
	a, s, ans, shown := modeHost(true)
	s.view.Store(true)
	first := modeCall(ctx, a, s, false)
	time.Sleep(50 * time.Millisecond)
	var wg sync.WaitGroup
	var busy, other atomic.Int32
	for i := 0; i < 2000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.setMode(ctx, s, new(bool), func(m modeMsg) {
				if m.Why == "busy" && m.View {
					busy.Add(1)
				} else {
					other.Add(1)
				}
			})
		}()
	}
	wg.Wait()
	if shown.Load() != 1 || busy.Load() != 2000 || other.Load() != 0 {
		t.Errorf("E5: окон %d busy %d other %d", shown.Load(), busy.Load(), other.Load())
	}
	// клиент «передумал» при открытом окне: view:true; затем человек жмёт «Разрешить»
	modeGot(t, modeCall(ctx, a, s, true), modeMsg{T: "mode", View: true, OK: true})
	ans <- true
	if m := <-first; m.Why != "cancel" || s.control() {
		t.Errorf("E6: клиент попросил просмотр при открытом окне, потом «Разрешить»: ответ %+v, control=%v", m, s.control())
	}
	// отказ → спам в течение modeWait
	modeGot(t, modeCall(ctx, a, s, true), modeMsg{T: "mode", View: true, OK: true})
	ch := modeCall(ctx, a, s, false)
	ans <- false
	modeGot(t, ch, modeMsg{T: "mode", View: true, Why: "denied"})
	var wait atomic.Int32
	for i := 0; i < 2000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.setMode(ctx, s, new(bool), func(m modeMsg) {
				if (m.Why == "wait" || m.Why == "busy") && m.View {
					wait.Add(1)
				}
			})
		}()
	}
	wg.Wait()
	if shown.Load() != 2 || wait.Load() != 2000 || s.control() {
		t.Errorf("E5: после отказа окон %d (ждали 2), wait %d, control %v", shown.Load(), wait.Load(), s.control())
	}
}

// E7 — настоящий канал: мусорные mode ничего не повышают (view не bool или нет поля — "bad" без окна), "mode" по
// каналу input не действует; после этого настоящая просьба с «Разрешить» повышает. (Буфер в просмотре — TestBrowserView;
// подмена clipSeq здесь гоняется с watchClip кончившейся сессии.)
func TestModeAccE2EJunk(t *testing.T) {
	defer func(w time.Duration, n int) { modeWait, modeMax = w, n }(modeWait, modeMax)
	modeWait, modeMax = 0, 10 // мусор с верным view открывает окна — не упереться в modeMax
	var ag *Agent
	var allow atomic.Bool
	var shown atomic.Int32
	e2eAgent = func(a *Agent) {
		ag = a
		a.Unattended = func() bool { return false }
		a.Confirm = func(string, string) Answer { return Allow }
		a.ConfirmControl = func(string, string) bool { shown.Add(1); return allow.Load() }
	}
	e2eCtl = func(t *testing.T, dc *webrtc.DataChannel, _ chan ctlMsg) {
		ch := rawCtl(dc)
		s := sessOf(ag)
		dc.SendText(`{"t":"mode","view":true}`)
		if m := waitMode(t, ch); m["ok"] != true || m["view"] != true {
			t.Errorf("в просмотр: %v", m)
		}
		for _, j := range []string{
			`{"t":"mode","view":false,"ok":true}`,
			`{"t":"mode","view":false,"ok":true,"why":"granted"}`,
			`{"t":"mode"}`,
			`{"t":"mode","view":"false"}`,
			`{"t":"mode","view":0}`,
			`{"t":"mode","view":null,"mode":true}`,
		} {
			before := shown.Load()
			dc.SendText(j)
			m := waitMode(t, ch)
			bad := !strings.Contains(j, `"view":false`)
			if s.control() || m["ok"] == true || m["view"] != true || bad && (m["why"] != "bad" || shown.Load() != before) {
				t.Errorf("E7: %s → %v, control=%v, окон +%d", j, m, s.control(), shown.Load()-before)
			}
		}
		allow.Store(true)
		before := shown.Load()
		e2eIn.SendText(`{"t":"mode","view":false}`)
		time.Sleep(300 * time.Millisecond)
		if s.control() || shown.Load() != before {
			t.Errorf("E7: mode по input: control=%v", s.control())
		}
		dc.SendText(`{"t":"mode","view":false}`)
		if m := waitMode(t, ch); m["ok"] != true || m["view"] != false {
			t.Errorf("повышение: %v", m)
		}
	}
	defer func() { e2eCtl = nil; e2eReset() }()
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
}

// E3 — гонка «клавиша ↔ переход в просмотр»: клавиша, прошедшая control() до смены режима и учтённая после release(),
// остаётся зажатой на хосте в «только просмотр».
func TestModeAccStuckKey(t *testing.T) {
	defer func(w, e time.Duration) { modeWait, e2eWait = w, e }(modeWait, e2eWait)
	modeWait, e2eWait = 0, 2*time.Minute
	var ag *Agent
	e2eAgent = func(a *Agent) {
		ag = a
		a.Unattended = func() bool { return false }
		a.Confirm = func(string, string) Answer { return Allow }
		a.ConfirmControl = func(string, string) bool { return true }
	}
	stuck, n := 0, 300 // без правки Д1 — ≈6 % (приёмка: 171/3000)
	e2eCtl = func(t *testing.T, dc *webrtc.DataChannel, _ chan ctlMsg) {
		ch := rawCtl(dc)
		s := sessOf(ag)
		held := func() int { s.keys.mu.Lock(); defer s.keys.mu.Unlock(); return len(s.keys.keys) }
		e2eIn.SendText(`{"t":"k","c":"ControlLeft","d":false}`)
		for i := 0; i < n; i++ {
			e2eIn.SendText(`{"t":"k","c":"KeyA","d":true}`)
			dc.SendText(`{"t":"mode","view":true}`)
			waitMode(t, ch)
			time.Sleep(2 * time.Millisecond)
			if !s.view.Load() {
				t.Fatal("не просмотр")
			}
			if held() != 0 {
				stuck++
			}
			dc.SendText(`{"t":"mode","view":false}`)
			waitMode(t, ch)
			e2eIn.SendText(`{"t":"k","c":"KeyA","d":false}`)
			for j := 0; j < 200 && held() != 0; j++ {
				time.Sleep(time.Millisecond)
			}
		}
	}
	defer func() { e2eCtl = nil; e2eReset() }()
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
	t.Logf("E3: клавиша осталась зажатой в «только просмотр» %d раз из %d", stuck, n)
	if stuck > 0 {
		t.Errorf("E3: залипшая клавиша в просмотре: %d из %d", stuck, n)
	}
}
