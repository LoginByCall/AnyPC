package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"anypc/hub"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/pion/webrtc/v4"
)

// TestSpaceSeal — Э4в, запечатанное доказательство: открывает только цель и только ключом члена; подмена любого байта,
// чужая цель, чужой ID, не член — не открывается; статус в "a" привязан к отпечаткам DTLS; поля сверки и обычного
// соединения одной длины.
func TestSpaceSeal(t *testing.T) {
	_, member, _ := ed25519.GenerateKey(nil)
	hpub, host, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	mpub := member.Public().(ed25519.PublicKey)
	keys := []ed25519.PublicKey{other.Public().(ed25519.PublicKey), mpub}
	now := time.Now().Unix()
	sx, h2c, err := sxMake(member, hpub, "123456789", now)
	if err != nil || len(sx) != sxLen {
		t.Fatalf("sxMake: %d %v", len(sx), err)
	}
	pub, tm, h, ok := sxOpen(host, keys, "123456789", sx)
	if !ok || !bytes.Equal(pub, mpub) || tm != now || !bytes.Equal(h, h2c) {
		t.Fatalf("цель не открыла: %v", ok)
	}
	for i := range sx {
		bad := bytes.Clone(sx)
		bad[i] ^= 0x80
		if _, _, _, ok := sxOpen(host, keys, "123456789", bad); ok {
			t.Fatalf("подмена байта %d принята", i)
		}
	}
	if _, _, _, ok := sxOpen(other, keys, "123456789", sx); ok {
		t.Error("открыл не тот хост")
	}
	if _, _, _, ok := sxOpen(host, keys, "123456780", sx); ok {
		t.Error("открылось под другим ID")
	}
	if _, _, _, ok := sxOpen(host, keys[:1], "123456789", sx); ok {
		t.Error("открылось без ключа члена")
	}
	if _, _, _, ok := sxOpen(host, keys, "123456789", sxRand(sxLen)); ok {
		t.Error("случайные байты открылись")
	}
	sx2, _, _ := sxMake(member, hpub, "123456789", now)
	if bytes.Equal(sx[:sxSaltLen], sx2[:sxSaltLen]) || bytes.Equal(sx, sx2) {
		t.Error("два доказательства одинаковы — хаб свяжет")
	}

	seal := &sxSeal{h2c: h2c, status: sxOK}
	ans := seal.answer("fpc", "fph")
	if st, ok := sxStatus(h2c, ans, "fpc", "fph"); !ok || st != sxOK {
		t.Errorf("статус: %d %v", st, ok)
	}
	if _, ok := sxStatus(h2c, ans, "fpc", "fpX"); ok {
		t.Error("статус открылся при других отпечатках (посредник в DTLS)")
	}
	rnd := (*sxSeal)(nil).answer("fpc", "fph")
	if len(rnd) != len(ans) || len(ans) != sxALen {
		t.Errorf("длины sx в \"a\": обычное %d, сверка %d", len(rnd), len(ans))
	}
	if _, ok := sxStatus(h2c, rnd, "fpc", "fph"); ok {
		t.Error("случайный sx в \"a\" открылся")
	}
}

// TestSpaceSealCheck — хост: свежее доказательство члена — место (sxOK) и соль в кэше; повтор того же — sxBusy;
// часы ±10 мин — sxSkew; не член и случайные байты — обычный connect (nil).
func TestSpaceSealCheck(t *testing.T) {
	_, member, _ := ed25519.GenerateKey(nil)
	hpub, host, _ := ed25519.GenerateKey(nil)
	a := &Agent{ID: "123456789", Key: host, SpaceSync: &fakeSync{members: []ed25519.PublicKey{member.Public().(ed25519.PublicKey)}}}
	sx, _, _ := sxMake(member, hpub, a.ID, time.Now().Unix())
	if pub, s := a.sxCheck(sx); s == nil || s.status != sxOK || pub == nil {
		t.Fatalf("свежее: %v", s)
	}
	if _, s := a.sxCheck(sx); s == nil || s.status != sxBusy {
		t.Errorf("повтор: %v", s)
	}
	old, _, _ := sxMake(member, hpub, a.ID, time.Now().Add(-syncSkew-time.Minute).Unix())
	if _, s := a.sxCheck(old); s == nil || s.status != sxSkew {
		t.Errorf("часы: %v", s)
	}
	_, stranger, _ := ed25519.GenerateKey(nil)
	sx3, _, _ := sxMake(stranger, hpub, a.ID, time.Now().Unix())
	if _, s := a.sxCheck(sx3); s != nil {
		t.Error("не член открыл")
	}
	if _, s := a.sxCheck(sxRand(sxLen)); s != nil {
		t.Error("случайные байты открылись")
	}
	if _, s := a.sxCheck(nil); s != nil {
		t.Error("старый клиент без поля")
	}
	a.SpaceSync = nil
	if _, s := a.sxCheck(sx); s != nil {
		t.Error("хост без сверки")
	}
	if len(a.sxSeen) != 1 {
		t.Errorf("кэш повтора: %d", len(a.sxSeen))
	}
}

// TestSpaceSyncHidden — Э4в: connect сверки и обычный connect программы (вступление, пропуск) хаб видит одинаковыми —
// тот же набор полей, та же длина; ключей членов в нём нет. Старый хост (v0.2.0) новое поле пропускает.
func TestSpaceSyncHidden(t *testing.T) {
	var mu sync.Mutex
	var got [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // хаб: записать connect, «нет хоста»
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		ctx := r.Context()
		wsjson.Write(ctx, c, hub.Msg{V: 1, Type: "hello", Data: json.RawMessage(`{}`)})
		var m hub.Msg
		if wsjson.Read(ctx, c, &m) != nil || m.Type != "connect" {
			return
		}
		mu.Lock()
		got = append(got, m.Data)
		mu.Unlock()
		wsjson.Write(ctx, c, hub.Msg{V: 1, Type: "error", Data: json.RawMessage(`"not_found"`)})
	}))
	t.Cleanup(srv.Close)
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	hpub, _, _ := ed25519.GenerateKey(nil)
	_, member, _ := ed25519.GenerateKey(nil)
	ctx := context.Background()
	if _, err := SpaceSync(ctx, SyncDial{Server: url, ID: "123456789", HostPub: hpub, Key: member, S: &fakeSync{}}); !errors.Is(err, ErrSpaceOffline) {
		t.Fatalf("сверка: %v", err)
	}
	noop := func(*webrtc.PeerConnection, func(error)) {}
	if err := hostDial(ctx, url, "123456789", connectReq{View: true}, noop); !errors.Is(err, ErrSpaceOffline) { // вступление, пропуск
		t.Fatalf("обычный: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("connect: %d", len(got))
	}
	var s, o map[string]json.RawMessage
	if json.Unmarshal(got[0], &s) != nil || json.Unmarshal(got[1], &o) != nil {
		t.Fatal("не JSON")
	}
	if ks, ko := slices.Sorted(maps.Keys(s)), slices.Sorted(maps.Keys(o)); !slices.Equal(ks, ko) {
		t.Errorf("поля: сверка %v, обычный %v", ks, ko)
	}
	if len(got[0]) != len(got[1]) || len(s["sx"]) != len(o["sx"]) {
		t.Errorf("длина: сверка %d (%s), обычный %d (%s)", len(got[0]), got[0], len(got[1]), got[1])
	}
	for k, v := range s {
		if k != "sx" && !bytes.Equal(v, o[k]) {
			t.Errorf("поле %s: сверка %s, обычный %s", k, v, o[k])
		}
	}
	for _, k := range [][]byte{member.Public().(ed25519.PublicKey), hpub} {
		b, _ := json.Marshal(k)
		if bytes.Contains(got[0], b[1:len(b)-1]) {
			t.Error("ключ в connect сверки")
		}
	}
	var old struct { // connectReq v0.2.0
		TURN string         `json:"turn"`
		RTT  map[string]int `json:"rtt"`
		CPub []byte         `json:"cpub"`
		VP9  bool           `json:"vp9"`
		View bool           `json:"view"`
	}
	if err := json.Unmarshal(got[0], &old); err != nil || !old.View {
		t.Errorf("старый хост: %v", err)
	}
}

// TestSpaceSyncConnect — Э4в на проводе: обычный connect нового клиента (случайный sx), без поля (старый клиент),
// с доказательством не члена или со сбитыми часами — offer как обычному и места сверки нет; свежее доказательство
// члена — offer и место; его повтор и второе на занятое место — offer как обычному, место одно; другой член проходит;
// идёт сессия — сверка и обычный получают одно и то же "busy".
func TestSpaceSyncConnect(t *testing.T) {
	url, r, host, d := syncRig(t)
	_, k2, _ := ed25519.GenerateKey(nil)
	host.mu.Lock()
	host.members = append(host.members, k2.Public().(ed25519.PublicKey))
	host.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.Sleep(100 * time.Millisecond) // замер TURN после регистрации кончился
	r.a.mu.Lock()
	r.a.rtt = map[string]int{"turn.example": 7}                     // offer несёт замеры хоста — у сверки тоже
	r.a.rttAt = map[string]time.Time{"": time.Now().Add(time.Hour)} // hello перед connect не перемерит
	r.a.mu.Unlock()
	var offer []string                    // поля последнего offer
	connect := func(body string) string { // каждый connect — своим WS (у хаба лимит connect на WS)
		ws, err := dial(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ws.CloseNow() })
		var m hub.Msg
		wsjson.Read(ctx, ws, &m) // hello
		wsjson.Write(ctx, ws, hub.Msg{V: 1, Type: "connect", To: "123456789", Data: json.RawMessage(body)})
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if wsjson.Read(rctx, ws, &m) != nil {
			return "нет ответа"
		}
		var why string
		json.Unmarshal(m.Data, &why)
		var o map[string]json.RawMessage
		json.Unmarshal(m.Data, &o)
		offer = slices.Sorted(maps.Keys(o))
		return m.Type + " " + why
	}
	req := func(sx []byte) string { b, _ := json.Marshal(connectReq{View: true, SX: sx}); return string(b) }
	places := func() (syncs, pend int) {
		r.a.mu.Lock()
		defer r.a.mu.Unlock()
		return len(r.a.syncs), len(r.a.pend)
	}
	drop := func() { // освободить места обычных входов (maxPending)
		r.a.DropPending()
		for i := 0; i < 50; i++ {
			if _, p := places(); p == 0 {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("места обычных входов не освободились")
	}
	hp := d.HostPub
	now := time.Now().Unix()
	_, stranger, _ := ed25519.GenerateKey(nil)
	strange, _, _ := sxMake(stranger, hp, "123456789", now)
	old, _, _ := sxMake(d.Key, hp, "123456789", now-int64((syncSkew+time.Minute)/time.Second))
	for name, body := range map[string]string{"случайный sx": req(sxRand(sxLen)), "без поля": `{"view":true}`, "не член": req(strange)} {
		if a := connect(body); a != "offer " {
			t.Errorf("%s: %s", name, a)
		}
	}
	if s, p := places(); s != 0 || p != 3 {
		t.Errorf("постороннему: мест сверки %d, обычных %d", s, p)
	}
	plain := offer
	drop()
	if a := connect(req(old)); a != "offer " {
		t.Errorf("часы: %s", a)
	}
	if s, _ := places(); s != 0 {
		t.Error("место сверки при сбитых часах")
	}
	drop()
	hold, _, _ := sxMake(d.Key, hp, "123456789", now)
	if a := connect(req(hold)); a != "offer " { // место занято (offer без ответа)
		t.Fatalf("член: %s", a)
	}
	if s, p := places(); s != 1 || p != 0 {
		t.Fatalf("член: мест сверки %d, обычных %d", s, p)
	}
	if !slices.Equal(offer, plain) || !slices.Contains(offer, "rtt") {
		t.Errorf("offer: сверка %v, обычный %v", offer, plain)
	}
	if a := connect(req(hold)); a != "offer " { // повтор хабом
		t.Errorf("повтор: %s", a)
	}
	again, _, _ := sxMake(d.Key, hp, "123456789", now)
	if a := connect(req(again)); a != "offer " {
		t.Errorf("второе на занятое место: %s", a)
	}
	if s, p := places(); s != 1 || p != 2 {
		t.Errorf("повтор и второе: мест сверки %d, обычных %d", s, p)
	}
	if _, err := SpaceSync(ctx, d); !errors.Is(err, ErrSpaceRefused) {
		t.Errorf("сверка при занятом месте: %v", err)
	}
	drop()
	d2 := d
	d2.Key = k2
	if _, err := SpaceSync(ctx, d2); err != nil {
		t.Errorf("другой член при занятом месте первого: %v", err)
	}
	r.a.mu.Lock()
	r.a.sess = &session{} // идёт сессия
	r.a.mu.Unlock()
	busy, _, _ := sxMake(k2, hp, "123456789", time.Now().Unix())
	if a, b := connect(req(busy)), connect(req(sxRand(sxLen))); a != "error busy" || a != b {
		t.Errorf("идёт сессия: сверка %q, обычный %q", a, b)
	}
	r.a.mu.Lock()
	r.a.sess = nil
	r.a.mu.Unlock()
}
