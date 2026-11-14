package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"anypc/hub"

	"github.com/coder/websocket/wsjson"
)

// fakeSync — SpaceSyncer без формата: M — непрозрачные байты; gate — пускать ли; members — ключи членов (nil — любой);
// got — что пришло в SyncApply.
type fakeSync struct {
	mu      sync.Mutex
	m       []byte
	gate    bool
	members []ed25519.PublicKey
	recs    [][]byte
	got     [][]byte
	gated   int
}

func (f *fakeSync) SyncKey(pub ed25519.PublicKey) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.members {
		if bytes.Equal(k, pub) {
			return true
		}
	}
	return f.members == nil
}

func (f *fakeSync) SyncGate(ed25519.PublicKey, []byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gated++
	if !f.gate {
		return nil
	}
	return bytes.Clone(f.m)
}
func (f *fakeSync) SyncRecs([]byte) [][]byte { f.mu.Lock(); defer f.mu.Unlock(); return f.recs }
func (f *fakeSync) SyncApply(p []byte, recs [][]byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(append(f.got, recs...), p)
	if len(recs) > 0 { // «принял» записи и M другой стороны
		f.m = bytes.Clone(p)
	}
	return bytes.Clone(f.m)
}

func (f *fakeSync) apply() [][]byte { f.mu.Lock(); defer f.mu.Unlock(); return f.got }

// syncRig — хост 123456789 со сверкой; ckey — ключ члена (в members хоста).
func syncRig(t *testing.T) (string, *spaceRig, *fakeSync, SyncDial) {
	url := local(t)
	_, ckey, _ := ed25519.GenerateKey(nil)
	host := &fakeSync{m: []byte("M1"), gate: true, members: []ed25519.PublicKey{ckey.Public().(ed25519.PublicKey)}}
	r := spaceHost(t, url, "123456789", func(r *spaceRig) { r.a.SpaceSync = host })
	cli := &fakeSync{m: []byte("M3"), gate: true, recs: [][]byte{[]byte("R2")}}
	return url, r, host, SyncDial{Server: url, ID: "123456789", HostPub: r.a.Key.Public().(ed25519.PublicKey), Key: ckey, S: cli}
}

// TestSpaceSyncWire — Э4, обмен сверки по сети: отставший хост получает записи цепочки по порядку и M клиента;
// клиент получает M хоста после приёма. Вход не выполняется: неудач нет, места сессии сверка не занимает. Отказы:
// gate хоста — refused; под ID другой ключ — ErrSpaceIDKey (С4) без ключа хоста; хост без сверки — ErrSpaceOld;
// клиент не шлёт свой M хосту, которого его gate не пускает; лишние записи — отказ.
func TestSpaceSyncWire(t *testing.T) {
	url, r, host, d := syncRig(t)
	hm, err := SpaceSync(context.Background(), d)
	if err != nil || string(hm) != "M3" {
		t.Fatalf("сверка: %q %v", hm, err)
	}
	if got := host.apply(); len(got) != 2 || string(got[0]) != "R2" || string(got[1]) != "M3" {
		t.Errorf("хост получил %q", got)
	}
	if f, _ := lock(r.a); f != 0 {
		t.Errorf("неудач у хоста %d", f)
	}
	r.a.mu.Lock()
	busy, left := r.a.sess != nil, len(r.a.syncs)
	r.a.mu.Unlock()
	if busy {
		t.Error("сверка заняла место сессии")
	}
	if left != 0 {
		time.Sleep(time.Second) // место освобождается после ответа
		r.a.mu.Lock()
		left = len(r.a.syncs)
		r.a.mu.Unlock()
		if left != 0 {
			t.Error("место сверки не освободилось")
		}
	}

	host.mu.Lock()
	host.gate = false
	host.mu.Unlock()
	if _, err := SpaceSync(context.Background(), d); !errors.Is(err, ErrSpaceRefused) {
		t.Errorf("gate хоста: %v", err)
	}
	host.mu.Lock()
	host.gate = true
	host.mu.Unlock()

	cli := d.S.(*fakeSync)
	cli.mu.Lock()
	cli.gate = false
	cli.mu.Unlock()
	n := len(host.apply())
	host.mu.Lock()
	g := host.gated
	host.mu.Unlock()
	if _, err := SpaceSync(context.Background(), d); !errors.Is(err, ErrSpaceRefused) {
		t.Errorf("gate клиента: %v", err)
	}
	host.mu.Lock()
	g2 := host.gated
	host.mu.Unlock()
	if g2 != g || len(host.apply()) != n {
		t.Error("клиент отдал свой M хосту, которого его gate не пускает")
	}
	cli.mu.Lock()
	cli.gate = true
	for range maxSyncRecs + 1 {
		cli.recs = append(cli.recs, []byte("Rx"))
	}
	cli.mu.Unlock()
	if _, err := SpaceSync(context.Background(), d); !errors.Is(err, ErrSpaceRefused) {
		t.Errorf("записей сверх %d: %v", maxSyncRecs, err)
	}
	cli.mu.Lock()
	cli.recs = nil
	cli.mu.Unlock()

	other, _, _ := ed25519.GenerateKey(nil)
	d2 := d
	d2.HostPub = other
	if _, err := SpaceSync(context.Background(), d2); !errors.Is(err, ErrSpaceIDKey) {
		t.Errorf("чужой ключ под ID: %v", err)
	}
	old := spaceHost(t, url, "223456789") // SpaceSync == nil — как старая версия
	d2.ID, d2.HostPub = "223456789", old.a.Key.Public().(ed25519.PublicKey)
	if _, err := SpaceSync(context.Background(), d2); !errors.Is(err, ErrSpaceOld) {
		t.Errorf("старый хост: %v", err)
	}
	if f, _ := lock(old.a); f != 0 {
		t.Errorf("неудач у старого хоста %d", f)
	}
}

// TestSpaceSyncSigs — подписи сверяются на обеих сторонах: подпись хоста не та — клиент кончает (ErrSpaceHostKey) и
// M не отдаёт; подпись клиента в "b" не та — хост отказывает ("denied") и M не отдаёт.
func TestSpaceSyncSigs(t *testing.T) {
	_, _, host, d := syncRig(t)
	t.Cleanup(func() { syncTamper.Store("") })
	syncTamper.Store("host")
	if _, err := SpaceSync(context.Background(), d); !errors.Is(err, ErrSpaceHostKey) {
		t.Errorf("подпись хоста не та: %v", err)
	}
	syncTamper.Store("client")
	if _, err := SpaceSync(context.Background(), d); !errors.Is(err, ErrSpaceRefused) {
		t.Errorf("подпись клиента не та: %v", err)
	}
	host.mu.Lock()
	g := host.gated
	host.mu.Unlock()
	if g != 0 || len(host.apply()) != 0 {
		t.Error("обмен без доказанных ключей")
	}
}

// TestSpaceSyncConnect — доказательство в connect: посторонний (без подписи члена) места не получает вовсе — поток
// его connect не мешает члену; подпись не члена — rights; часы ±10 мин — skew; место — одно на ключ (второе — busy),
// другой член проходит.
func TestSpaceSyncConnect(t *testing.T) {
	url, r, host, d := syncRig(t)
	_, k2, _ := ed25519.GenerateKey(nil)
	host.mu.Lock()
	host.members = append(host.members, k2.Public().(ed25519.PublicKey))
	host.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ws, err := dial(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	var hello hub.Msg
	wsjson.Read(ctx, ws, &hello)
	answers := make(chan string, 64)
	go func() {
		for {
			var m hub.Msg
			if wsjson.Read(ctx, ws, &m) != nil {
				return
			}
			var why string
			json.Unmarshal(m.Data, &why)
			answers <- m.Type + " " + why
		}
	}()
	connect := func(req connectReq) string {
		b, _ := json.Marshal(req)
		wsjson.Write(ctx, ws, hub.Msg{V: 1, Type: "connect", To: "123456789", Data: b})
		select {
		case a := <-answers:
			return a
		case <-time.After(5 * time.Second):
			return "нет ответа"
		}
	}
	if a := connect(connectReq{View: true, Sync: true}); a != "error rights" {
		t.Errorf("без подписи: %s", a)
	}
	_, stranger, _ := ed25519.GenerateKey(nil)
	now := time.Now().Unix()
	sreq := connectReq{View: true, Sync: true, SPub: stranger.Public().(ed25519.PublicKey), ST: now, SSig: ed25519.Sign(stranger, syncProof("123456789", now))}
	if a := connect(sreq); a != "error rights" {
		t.Errorf("не член: %s", a)
	}
	r.a.mu.Lock()
	n := len(r.a.syncs)
	r.a.mu.Unlock()
	if n != 0 {
		t.Errorf("постороннему выделено мест: %d", n)
	}
	old := now - int64(11*time.Minute/time.Second)
	skew := connectReq{View: true, Sync: true, SPub: d.Key.Public().(ed25519.PublicKey), ST: old, SSig: ed25519.Sign(d.Key, syncProof("123456789", old))}
	if a := connect(skew); a != "error skew" {
		t.Errorf("часы: %s", a)
	}
	hold := connectReq{View: true, Sync: true, SPub: d.Key.Public().(ed25519.PublicKey), ST: now, SSig: ed25519.Sign(d.Key, syncProof("123456789", now))}
	if a := connect(hold); a != "offer " { // место занято (offer без ответа), ключ — член
		t.Fatalf("член: %s", a)
	}
	if _, err := SpaceSync(ctx, d); !errors.Is(err, ErrSpaceRefused) {
		t.Errorf("второе место на тот же ключ: %v", err)
	}
	d2 := d
	d2.Key = k2
	if _, err := SpaceSync(ctx, d2); err != nil {
		t.Errorf("другой член при занятом месте первого: %v", err)
	}
}
