package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anypc/agent"
)

// AppKit — главный поток и в тестах: тесты идут горутиной, главный поток ждёт первого окна (window_darwin.go).
func TestMain(m *testing.M) { mainLoop(func() { os.Exit(m.Run()) }) }

// TestMacWindowLive — своё окно на настоящем экране: страница с токеном по одноразовому коду, WebRTC и канал данных
// в окне, родной полный экран окна ПК, значок в строке меню. Запуск: ANYPC_MACWIN_LIVE=1 go test ./app -run MacWindow -v
func TestMacWindowLive(t *testing.T) {
	if os.Getenv("ANYPC_MACWIN_LIVE") == "" {
		t.Skip("ANYPC_MACWIN_LIVE не задан")
	}
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	page, _ := shimmed("ws://127.0.0.1:1/ws", "toklive") // хабов нет: фрейм не выходит в сеть
	once := &onceCode{}
	info := func() map[string]any {
		return map[string]any{"id": cfg.ID, "users": []any{}, "keys": []any{}, "version": "test"}
	}
	go http.Serve(l, handler(addr, "toklive", page, cfg, &agent.Agent{}, nil, info, newFiles(t.TempDir()), once))
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	go macTray(ctx, cfg.ID, func() {}, func() {})
	w := macWins{base: "http://" + addr, issue: once.issue}
	s, err := w.screens(ctx)
	t.Logf("мониторы: %+v %v", s, err)
	if err != nil || len(s) == 0 {
		t.Fatal("нет мониторов")
	}
	main := nativeOpen("http://"+addr+"/?n="+once.issue(), "AnyPC", -1, true, "")
	if main == 0 {
		t.Fatal("окно не создано")
	}
	defer nativeClose(main)
	if err := wkUntil(ctx, main, "location.search.includes('t=toklive') && typeof hostInfo === 'function'"); err != nil {
		t.Fatal("страница с токеном не открылась:", err)
	}
	probe := `(async () => { const r = {pc: typeof RTCPeerConnection, sec: isSecureContext, md: typeof navigator.mediaDevices, gum: typeof navigator.mediaDevices?.getUserMedia, fs: String(window.fullscreen).includes('webkit')};
  const a = new RTCPeerConnection(), b = new RTCPeerConnection(); a.onicecandidate = e => e.candidate && b.addIceCandidate(e.candidate); b.onicecandidate = e => e.candidate && a.addIceCandidate(e.candidate);
  const ch = a.createDataChannel('x'), got = new Promise(res => { b.ondatachannel = e => { e.channel.onmessage = m => res(m.data); }; });
  ch.onopen = () => ch.send('ping'); await a.setLocalDescription(); await b.setRemoteDescription(a.localDescription); await b.setLocalDescription(); await a.setRemoteDescription(b.localDescription);
  r.dc = await Promise.race([got, new Promise(res => setTimeout(() => res('timeout'), 4000))]); return r; })()`
	r, err := wkEval(ctx, main, probe)
	t.Logf("главное окно: %s %v", r, err)
	if !strings.Contains(r, `"pc":"function"`) || !strings.Contains(r, `"dc":"ping"`) || !strings.Contains(r, `"fs":true`) {
		t.Error("в окне нет WebRTC, канала данных или родного полного экрана")
	}
	if err := w.open(ctx, "123456789", 0, map[string]string{"mine": `[{"id":"123456789","name":"Офис"}]`}); err != nil {
		t.Fatal("окно ПК:", err)
	}
	pc := main + 1 // номера окон идут подряд (window_darwin.m)
	defer nativeClose(pc)
	time.Sleep(2500 * time.Millisecond) // анимация перехода в свой Space
	r, err = wkEval(ctx, pc, `({full: innerWidth === screen.width && innerHeight === screen.height, mine: localStorage.getItem('mine'), tok: location.search.includes('t=toklive'), size: [innerWidth, innerHeight, screen.width, screen.height, screenX, screenY].join(), fsbody: [...document.querySelectorAll('#frames iframe')].map(f => f.contentDocument.body.className).join()})`)
	t.Logf("окно ПК: %s %v", r, err)
	if hostLocked() { // экран заблокирован: свой Space окну не дают (windowDidFailToEnterFullScreen) — страница вышла из «fs»
		t.Log("экран заблокирован: полный экран не проверить")
		r = strings.Replace(r, `"full":false`, `"full":true`, 1)
	}
	if !strings.Contains(r, `"full":true`) || !strings.Contains(r, "Офис") || !strings.Contains(r, `"tok":true`) {
		t.Error("окно ПК не во весь экран или без переноса")
	}
	time.Sleep(3 * time.Second) // снимок экрана (screencapture) снаружи
}
