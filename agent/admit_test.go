package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/pake"
)

// admitRig — Ч12б: поручитель P с вступлением без пароля. Ключ владельца — случайный (в app он из фразы и osalt),
// окно «Пустить?» — answer теста; asks — что показали в окне. Всё, что тест меняет при работающем P, — атомарно.
type admitRig struct {
	*spaceRig
	url    string
	owner  ed25519.PrivateKey
	osalt  []byte
	why    atomic.Value // string: ответ SpaceOwner ("" — пускает)
	shut   atomic.Bool  // LoginShut
	view   atomic.Bool  // «Только показ экрана»
	codes  atomic.Int32 // вызовы OTP
	amu    sync.Mutex
	asks   []AdmitReq
	answer func(context.Context, AdmitReq) AdmitResult
	jid    string // id в SpaceJoin
}

func yes(context.Context, AdmitReq) AdmitResult { return AdmitYes }
func no(context.Context, AdmitReq) AdmitResult  { return AdmitNo }

func admitHost(t *testing.T, opt ...func(*admitRig)) *admitRig {
	t.Helper()
	url := local(t)
	_, owner, _ := ed25519.GenerateKey(nil)
	r := &admitRig{url: url, owner: owner, osalt: []byte("osalt-0123456789"), answer: yes}
	r.why.Store("")
	r.spaceRig = spaceHost(t, url, "123456789", func(s *spaceRig) {
		r.spaceRig = s
		s.a.SpaceOwner = func(salt0 []byte) ([]byte, ed25519.PublicKey, string) {
			if w := r.why.Load().(string); w != "" {
				return nil, nil, w
			}
			if !bytes.Equal(salt0, salt) {
				return nil, nil, "none"
			}
			return bytes.Clone(r.osalt), r.owner.Public().(ed25519.PublicKey), ""
		}
		s.a.SpaceAdmit = func(ctx context.Context, q AdmitReq) AdmitResult {
			r.amu.Lock()
			r.asks = append(r.asks, q)
			f := r.answer
			r.amu.Unlock()
			return f(ctx, q)
		}
		join, otp := s.a.SpaceJoin, s.a.OTP
		s.a.SpaceJoin = func(sl, m []byte, pub ed25519.PublicKey, id string) error {
			r.amu.Lock()
			r.jid = id
			r.amu.Unlock()
			return join(sl, m, pub, id)
		}
		s.a.OTP = func(u, c string) (bool, bool) { r.codes.Add(1); return otp(u, c) }
		s.a.LoginShut = func(string) bool { return r.shut.Load() }
		s.a.ViewOnly = func() bool { return r.view.Load() }
		for _, f := range opt {
			f(r)
		}
	})
	return r
}

// fresh — следующий код TOTP снова годен (тест: защита от повтора у владельца секрета не мешает следующей попытке).
func (r *admitRig) fresh() string {
	r.spaceRig.owner.mu.Lock()
	r.spaceRig.owner.last = 0
	r.spaceRig.owner.mu.Unlock()
	return r.spaceRig.owner.code()
}

func (r *admitRig) asked() []AdmitReq {
	r.amu.Lock()
	defer r.amu.Unlock()
	return append([]AdmitReq(nil), r.asks...)
}

func (r *admitRig) setAnswer(f func(context.Context, AdmitReq) AdmitResult) {
	r.amu.Lock()
	r.answer = f
	r.amu.Unlock()
}

// noPause — снять паузу окна после отказа (тест следующего шага).
func (r *admitRig) noPause() {
	r.a.mu.Lock()
	r.a.admitNext = time.Time{}
	r.a.mu.Unlock()
}

// jlock — лестница вступления P: неудачи подряд и сколько ещё заперта.
func jlock(a *Agent) (int, time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.joinFails, time.Until(a.joinUntil)
}

// ownerLocks — лестницы входа записи по умолчанию и хоста не тронуты (вход владельца открыт).
func ownerLocks(t *testing.T, a *Agent) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	n := a.names[""]
	if a.fails != 0 || a.otpFails != 0 || !a.lockUntil.IsZero() || !a.otpLock.IsZero() || n != nil && (n.fails != 0 || n.otpFails != 0) {
		t.Errorf("вступление тронуло лестницы входа: хост %d/%d, запись %+v", a.fails, a.otpFails, n)
	}
}

// joinDial — новый ПК N с ключом key: ID 987654321, имя «Ноутбук», ключ владельца owner (nil — свой у P).
func (r *admitRig) joinDial(key, owner ed25519.PrivateKey, code string, stages *[]string, signed *atomic.Bool) SpaceDial {
	if owner == nil {
		owner = r.owner
	}
	var smu sync.Mutex
	return SpaceDial{Server: r.url, ID: "123456789", Key: key, Code: code, Self: "987654321", Name: "Ноутбук",
		OwnerKey: func(osalt []byte) (ed25519.PrivateKey, error) {
			if !bytes.Equal(osalt, r.osalt) {
				return nil, errors.New("тест: не та соль")
			}
			return bytes.Clone(owner), nil // клиент стирает ключ после подписи
		},
		Stage: func(s string) {
			if stages != nil {
				smu.Lock()
				*stages = append(*stages, s)
				smu.Unlock()
			}
		},
		Sign: func(m []byte, _ ed25519.PublicKey, _ ...[]byte) ([]byte, error) {
			if signed != nil {
				signed.Store(true)
			}
			return append(bytes.Clone(m), "+N"...), nil
		}}
}

func newKey() ed25519.PrivateKey { _, k, _ := ed25519.GenerateKey(nil); return k }

// TestSpaceJoinAdmit — Ч12б, решения A' и B, happy-path: без пароля — код, доказательство фразы, окно «Пустить?» с
// ID, именем и отпечатком ключа N, «Разрешить» — P принимает M под показанным ID. Сессия вступления — не вход:
// плашки и видео нет. Код, ключ владельца и состав — не в журнале.
func TestSpaceJoinAdmit(t *testing.T) {
	var logs syncBuf
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	r := admitHost(t)
	nkey := newKey()
	var stages []string
	code := r.fresh()
	out, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, code, &stages, nil))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "M-SECRET-MARK-1+N" {
		t.Errorf("N получил %q", out)
	}
	asks := r.asked()
	if len(asks) != 1 || asks[0].ID != "987654321" || asks[0].Name != "Ноутбук" || asks[0].FP != pake.KeyFingerprint(nkey.Public().(ed25519.PublicKey)) {
		t.Errorf("окно «Пустить?»: %+v", asks)
	}
	r.mu.Lock()
	joined, jp := r.joined, r.joinPub
	r.mu.Unlock()
	if !bytes.Equal(joined, out) || !bytes.Equal(jp, nkey.Public().(ed25519.PublicKey)) {
		t.Errorf("P принял %q с ключом %x", joined, jp)
	}
	r.amu.Lock()
	jid := r.jid
	r.amu.Unlock()
	if jid != "987654321" {
		t.Errorf("SpaceJoin получил ID %q, а в окне был 987654321", jid)
	}
	if got := strings.Join(stages, ","); got != "link,auth,admit,list" {
		t.Errorf("стадии: %s", got)
	}
	ownerLocks(t, r.a)
	l := logs.String()
	if strings.Contains(l, "вход выполнен") {
		t.Error("сессия вступления стала входом (экран)")
	}
	for _, s := range []string{code, "M-SECRET-MARK", string(r.owner.Seed())} {
		if strings.Contains(l, s) {
			t.Errorf("в журнале секрет %q", s)
		}
	}
	if !strings.Contains(l, "окно «Пустить?»") || !strings.Contains(l, "вступление разрешено") {
		t.Error("окно и ответ — не в журнале")
	}
}

// TestSpaceJoinAuthWait — приёмка Б1: «Разрешить» нажали раньше authWait, а человек на новом ПК ещё смотрит «Это все
// ваши ПК?» дольше authWait — таймер входа сессию вступления не рвёт.
func TestSpaceJoinAuthWait(t *testing.T) {
	defer func(d time.Duration) { authWait = d }(authWait)
	authWait = 2 * time.Second
	r := admitHost(t)
	d := r.joinDial(newKey(), nil, r.fresh(), nil, nil)
	d.Confirm = 20 * time.Second
	d.Sign = func(m []byte, _ ed25519.PublicKey, _ ...[]byte) ([]byte, error) {
		time.Sleep(4 * time.Second) // человек читает состав
		return append(bytes.Clone(m), "+N"...), nil
	}
	if _, err := SpaceJoin(context.Background(), d); err != nil {
		t.Fatalf("вступление после быстрого «Разрешить»: %v", err)
	}
}

// TestSpaceJoinAdmitDeny — «Отклонить»: отказ declined, состава N не получил; пауза окна общая по хосту — другой ID и
// ключ её не обходят (later без окна); после паузы окно снова; второй отказ подряд — пауза вдвое дольше; «Разрешить»
// сбрасывает паузу. Отказы окна — не неудачи входа и не неудачи вступления.
func TestSpaceJoinAdmitDeny(t *testing.T) {
	defer func(e time.Duration) { admitEvery = e }(admitEvery)
	admitEvery = time.Second
	r := admitHost(t, func(r *admitRig) { r.answer = no })
	var signed atomic.Bool
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, &signed)); !errors.Is(err, ErrSpaceDeclined) || !errors.Is(err, ErrSpaceRefused) {
		t.Fatalf("«Отклонить»: %v", err)
	}
	if signed.Load() || len(r.asked()) != 1 {
		t.Fatalf("после «Отклонить» состав %v, окон %d", signed.Load(), len(r.asked()))
	}
	var sw SpaceWaitError
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.As(err, &sw) || sw.Secs != 1 || !errors.Is(err, ErrSpaceLater) {
		t.Errorf("пауза в отказе: %v (%d с)", err, sw.Secs)
	}
	if len(r.asked()) != 1 {
		t.Fatalf("окно во время паузы: %d", len(r.asked()))
	}
	d := r.joinDial(newKey(), nil, r.fresh(), nil, nil)
	d.Self = "111222333"
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceLater) || len(r.asked()) != 1 {
		t.Errorf("другой ID и ключ во время паузы: %v, окон %d", err, len(r.asked()))
	}
	time.Sleep(admitEvery)
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceDeclined) || len(r.asked()) != 2 {
		t.Fatalf("после паузы: %v, окон %d", err, len(r.asked()))
	}
	time.Sleep(admitEvery + 200*time.Millisecond) // вторая пауза — 2 с: через 1,2 с ещё идёт
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceLater) || len(r.asked()) != 2 {
		t.Errorf("пауза не выросла: %v, окон %d", err, len(r.asked()))
	}
	time.Sleep(admitEvery)
	r.setAnswer(yes)
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); err != nil {
		t.Fatalf("после второй паузы «Разрешить»: %v", err)
	}
	r.a.mu.Lock()
	n, next := r.a.admitN, r.a.admitNext
	r.a.mu.Unlock()
	if n != 0 || !next.IsZero() {
		t.Errorf("«Разрешить» не сбросило паузу: %d %v", n, next)
	}
	ownerLocks(t, r.a)
	if f, _ := jlock(r.a); f != 0 {
		t.Errorf("отказы окна посчитаны неудачами вступления: %d", f)
	}
}

// TestSpaceJoinAdmitTimeout — окно без ответа весь срок: отказ noanswer (не declined); окно не появилось — nowin, без
// паузы (следующее вступление снова с окном).
func TestSpaceJoinAdmitTimeout(t *testing.T) {
	r := admitHost(t, func(r *admitRig) {
		r.answer = func(context.Context, AdmitReq) AdmitResult { return AdmitNoAnswer }
	})
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceNoAnswer) || errors.Is(err, ErrSpaceDeclined) {
		t.Errorf("нет ответа: %v", err)
	}
	r.noPause()
	r.setAnswer(func(context.Context, AdmitReq) AdmitResult { return AdmitNoWindow })
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceNoWindow) {
		t.Errorf("окно не появилось: %v", err)
	}
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceNoWindow) || len(r.asked()) != 3 {
		t.Errorf("после «окна нет» — пауза: %v, окон %d", err, len(r.asked()))
	}
}

// TestSpaceJoinClientGone — вступающий ушёл, пока окно открыто: окно закрывается (ctx), «Разрешить» после ухода не
// засчитывается; ушёл сразу (раньше AskDelay) — паузы нет; второго окна одновременно с первым не бывает.
func TestSpaceJoinClientGone(t *testing.T) {
	defer func(d time.Duration) { AskDelay = d }(AskDelay)
	AskDelay = 3 * time.Second
	var logs syncBuf
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	var open, maxOpen, closed atomic.Int32
	r := admitHost(t, func(r *admitRig) {
		r.answer = func(ctx context.Context, _ AdmitReq) AdmitResult {
			n := open.Add(1)
			for m := maxOpen.Load(); n > m && !maxOpen.CompareAndSwap(m, n); m = maxOpen.Load() {
			}
			defer open.Add(-1)
			select {
			case <-ctx.Done():
				closed.Add(1)
			case <-time.After(15 * time.Second):
			}
			return AdmitYes // «Разрешить» уже после ухода
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	d := r.joinDial(newKey(), nil, r.fresh(), nil, nil)
	var once sync.Once
	d.Stage = func(s string) {
		if s == "admit" {
			once.Do(func() { time.AfterFunc(300*time.Millisecond, cancel) })
		}
	}
	if _, err := SpaceJoin(ctx, d); err == nil {
		t.Fatal("вступление ушедшего прошло")
	}
	for end := time.Now().Add(5 * time.Second); closed.Load() == 0 && time.Now().Before(end); {
		time.Sleep(50 * time.Millisecond)
	}
	if closed.Load() != 1 {
		t.Fatal("окно не закрыто после ухода вступающего")
	}
	time.Sleep(300 * time.Millisecond)
	if strings.Contains(logs.String(), "вступление разрешено") {
		t.Error("«Разрешить» после ухода засчитано")
	}
	r.setAnswer(yes)
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); err != nil {
		t.Errorf("после ухода — пауза или окно открыто: %v", err)
	}
	if maxOpen.Load() > 1 {
		t.Errorf("одновременно окон: %d", maxOpen.Load())
	}
}

// TestSpaceJoinGoneLate — приёмка круга 2, Б1: окно провисело дольше AskDelay, вступающий ушёл — как «нет ответа»:
// пауза растёт (иначе знающий код и фразу держал бы окно, уходил и через миг открывал снова).
func TestSpaceJoinGoneLate(t *testing.T) {
	defer func(d time.Duration) { AskDelay = d }(AskDelay)
	AskDelay = 300 * time.Millisecond
	r := admitHost(t, func(r *admitRig) {
		r.answer = func(ctx context.Context, _ AdmitReq) AdmitResult { <-ctx.Done(); return AdmitNo }
	})
	ctx, cancel := context.WithCancel(context.Background())
	d := r.joinDial(newKey(), nil, r.fresh(), nil, nil)
	var once sync.Once
	d.Stage = func(s string) {
		if s == "admit" {
			once.Do(func() { time.AfterFunc(time.Second, cancel) })
		}
	}
	SpaceJoin(ctx, d)
	for end := time.Now().Add(5 * time.Second); r.a.admitLeft() == 0 && time.Now().Before(end); {
		time.Sleep(50 * time.Millisecond)
	}
	if r.a.admitLeft() == 0 {
		t.Fatal("уход после AskDelay — без паузы")
	}
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) { // сессия ушедшего освобождена
		r.a.mu.Lock()
		free := r.a.sess == nil
		r.a.mu.Unlock()
		if free {
			break
		}
	}
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceLater) || len(r.asked()) != 1 {
		t.Errorf("сразу после ухода: %v, окон %d", err, len(r.asked()))
	}
}

// TestSpaceJoinSlow — код не пришёл за authWait, доказательство — за proofWait: свой отказ late (не про пароль).
func TestSpaceJoinSlow(t *testing.T) {
	defer func(a, p time.Duration) { authWait, proofWait = a, p }(authWait, proofWait)
	authWait, proofWait = time.Second, time.Second
	r := admitHost(t)
	joinCodeHook = func() { time.Sleep(1500 * time.Millisecond) }
	_, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil))
	joinCodeHook = nil
	if !errors.Is(err, ErrSpaceSlowHere) {
		t.Errorf("код опоздал: %v", err)
	}
	d := r.joinDial(newKey(), nil, r.fresh(), nil, nil)
	ok := d.OwnerKey
	d.OwnerKey = func(s []byte) (ed25519.PrivateKey, error) { time.Sleep(1500 * time.Millisecond); return ok(s) }
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceSlowHere) {
		t.Errorf("доказательство опоздало: %v", err)
	}
	if len(r.asked()) != 0 {
		t.Errorf("окон %d", len(r.asked()))
	}
}

// TestInputChannel — приёмка круга 2, Б3: событие канала input при открытом окне «Пустить?» этой сессии до хоста не
// доходит; после решения — доходит.
func TestInputChannel(t *testing.T) {
	var got atomic.Int32
	defer func(f func(event, *Monitor) error) { inputSend = f }(inputSend)
	inputSend = func(event, *Monitor) error { got.Add(1); return nil }
	var s session
	s.authed.Store(true)
	s.admitBlock.Store(true)
	bad := 0
	ev := []byte(`{"t":"m","x":100,"y":100}`)
	s.inputMsg(ev, &bad)
	if got.Load() != 0 {
		t.Fatal("ввод дошёл при открытом окне")
	}
	s.admitBlock.Store(false)
	s.inputMsg(ev, &bad)
	if got.Load() != 1 {
		t.Errorf("после окна ввод не дошёл: %d", got.Load())
	}
}

// TestSpaceJoinOneWindow — пока окно открыто (в том числе ушедшему клиенту, если окно ОС не закрыть), второе
// вступление — later без окна.
func TestSpaceJoinOneWindow(t *testing.T) {
	r := admitHost(t)
	r.a.mu.Lock()
	r.a.admitOpen = true
	r.a.mu.Unlock()
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceLater) || len(r.asked()) != 0 {
		t.Errorf("второе окно при открытом: %v, окон %d", err, len(r.asked()))
	}
	r.a.mu.Lock()
	r.a.admitOpen = false
	r.a.mu.Unlock()
}

// TestSpaceJoinBadCode — неверный код: неудача вступления, соль владельца не отдана (фразу не проверить), окна нет;
// лестницы входа владельца не тронуты.
func TestSpaceJoinBadCode(t *testing.T) {
	r := admitHost(t)
	code := r.fresh()
	bad := "000000"
	if code == bad {
		bad = "111111"
	}
	d := r.joinDial(newKey(), nil, bad, nil, nil)
	var salted atomic.Bool
	ok := d.OwnerKey
	d.OwnerKey = func(s []byte) (ed25519.PrivateKey, error) { salted.Store(true); return ok(s) }
	_, err := SpaceJoin(context.Background(), d)
	if !errors.Is(err, ErrSpaceBadCode) || !errors.Is(err, ErrSpaceAuth) {
		t.Errorf("неверный код: %v", err)
	}
	if salted.Load() || len(r.asked()) != 0 {
		t.Errorf("соль отдана %v, окон %d", salted.Load(), len(r.asked()))
	}
	if f, _ := jlock(r.a); f != 1 {
		t.Errorf("неудач вступления %d, ждали 1", f)
	}
	ownerLocks(t, r.a)
}

// TestSpaceJoinAnonLocksOwner — приёмка Б2: посторонний, зная только ID, пятью вступлениями с неверным кодом запирает
// только вступление — владелец входит паролем и кодом (и закреплённым ключом: лестница кодов записи не тронута).
func TestSpaceJoinAnonLocksOwner(t *testing.T) {
	r := admitHost(t)
	for i := 0; i < 6; i++ {
		c := []byte(r.fresh())
		c[0] = '0' + (c[0]-'0'+1)%10
		_, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, string(c), nil, nil))
		if !errors.Is(err, ErrSpaceBadCode) && !(i == 5 && errors.Is(err, ErrSpaceLockedThere)) {
			t.Fatalf("попытка %d: %v", i+1, err)
		}
	}
	if _, l := jlock(r.a); l <= 0 {
		t.Error("пять неверных кодов не заперли вступление")
	}
	ownerLocks(t, r.a)
	d := r.joinDial(newKey(), nil, r.fresh(), nil, nil) // владелец: пароль и код (вход, как до Ч12б)
	d.Password, d.OwnerKey = "secret123", nil
	if _, err := SpaceJoin(context.Background(), d); err != nil {
		t.Errorf("владелец паролем и кодом после анонимных вступлений: %v", err)
	}
}

// TestSpaceJoinBadPhrase — ключ не из той фразы: неудача вступления без окна; пятая подряд запирает вступление
// (и с верными кодом и фразой — locked), вход владельца не тронут.
func TestSpaceJoinBadPhrase(t *testing.T) {
	r := admitHost(t)
	nkey, wrong := newKey(), newKey()
	for i := 1; i <= 5; i++ {
		_, err := SpaceJoin(context.Background(), r.joinDial(nkey, wrong, r.fresh(), nil, nil))
		if !errors.Is(err, ErrSpaceBadPhrase) || !errors.Is(err, ErrSpaceAuth) {
			t.Fatalf("попытка %d: %v", i, err)
		}
		if f, _ := jlock(r.a); f != i {
			t.Fatalf("после %d неудач вступления %d", i, f)
		}
	}
	if len(r.asked()) != 0 {
		t.Errorf("окно после неверной фразы: %d", len(r.asked()))
	}
	if _, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceJoinLocked) || !errors.Is(err, ErrSpaceLockedThere) {
		t.Errorf("после 5 неудач: %v", err)
	}
	ownerLocks(t, r.a)
}

// TestSpaceJoinCodeLocked — лестница вступления заперта: и с верным кодом — locked, код не проверяется, окна нет.
func TestSpaceJoinCodeLocked(t *testing.T) {
	r := admitHost(t)
	r.a.mu.Lock()
	r.a.joinUntil = time.Now().Add(time.Minute)
	r.a.mu.Unlock()
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceLockedThere) {
		t.Errorf("заперто: %v", err)
	}
	if len(r.asked()) != 0 || r.codes.Load() != 0 {
		t.Errorf("окон %d, кодов проверено %d", len(r.asked()), r.codes.Load())
	}
	joinBadHostSig.Store(true) // заперто — хост и кода не просит: «otp» с плохой подписью клиент не увидит
	_, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil))
	joinBadHostSig.Store(false)
	if !errors.Is(err, ErrSpaceLockedThere) {
		t.Errorf("заперто — код всё же спрошен: %v", err)
	}
	r.a.mu.Lock()
	r.a.joinUntil = time.Time{}
	r.a.mu.Unlock()
	joinCodeHook = func() { // заперли, пока хост ждал код (параллельные попытки): код не проверяется
		r.a.mu.Lock()
		r.a.joinUntil = time.Now().Add(time.Minute)
		r.a.mu.Unlock()
	}
	_, err = SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil))
	joinCodeHook = nil
	if !errors.Is(err, ErrSpaceLockedThere) || r.codes.Load() != 0 || len(r.asked()) != 0 {
		t.Errorf("заперли во время ожидания кода: %v, кодов %d, окон %d", err, r.codes.Load(), len(r.asked()))
	}
	r.a.mu.Lock()
	r.a.joinUntil = time.Time{}
	r.a.mu.Unlock()
}

// TestSpaceJoinProofTransfer — доказательство из другого соединения (те же P, ключ N и фраза, другие DTLS-отпечатки)
// не принимается; подпись ключом владельца в чужом домене (подпись клиента, хоста) — тоже.
func TestSpaceJoinProofTransfer(t *testing.T) {
	r := admitHost(t)
	nkey := newKey()
	var first []byte
	joinSigHook = func(sig []byte) []byte { first = bytes.Clone(sig); return make([]byte, len(sig)) }
	defer func() { joinSigHook = nil }()
	if _, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceBadPhrase) {
		t.Fatalf("испорченная подпись: %v", err)
	}
	if len(first) != ed25519.SignatureSize {
		t.Fatal("тест: подпись первого соединения не снята")
	}
	joinSigHook = func([]byte) []byte { return first } // верное доказательство, но от первого соединения
	if _, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceBadPhrase) {
		t.Errorf("перенос в другое соединение: %v", err)
	}
	for name, f := range map[string]func(fc, fh string) []byte{
		"домен подписи клиента": func(fc, fh string) []byte {
			return ed25519.Sign(r.owner, []byte("anypc-client-v1\n123456789\n"+fc+"\n"+fh))
		},
		"домен подписи хоста": func(fc, fh string) []byte { return pake.HostSign(r.owner, "123456789", fc, fh) },
	} {
		joinFP = func(fc, fh string) { joinSigHook = func([]byte) []byte { return f(fc, fh) } }
		if _, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceBadPhrase) {
			t.Errorf("%s: %v", name, err)
		}
	}
	joinFP = nil
	if len(r.asked()) != 0 {
		t.Errorf("окно при чужом доказательстве: %d", len(r.asked()))
	}
}

// TestSpaceJoinBadClient — приёмка Б4: ключ нового ПК не доказан (испорченная подпись в "b"), вступление в запись по
// имени, без заявленного ID, «Только показ экрана» на поручителе — отказ без окна и без состава.
func TestSpaceJoinBadClient(t *testing.T) {
	r := admitHost(t)
	var signed atomic.Bool
	joinBadCSig.Store(true)
	_, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, &signed))
	joinBadCSig.Store(false)
	if !errors.Is(err, ErrSpaceAuth) {
		t.Errorf("недоказанный ключ: %v", err)
	}
	joinAsUser = "guest"
	_, err = SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, &signed))
	joinAsUser = ""
	if !errors.Is(err, ErrSpaceNotThere) {
		t.Errorf("запись по имени: %v", err)
	}
	d := r.joinDial(newKey(), nil, r.fresh(), nil, &signed)
	d.Self = ""
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceNotThere) {
		t.Errorf("без ID: %v", err)
	}
	d.Self = "123456789" // ID самого поручителя
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceNotThere) {
		t.Errorf("ID поручителя: %v", err)
	}
	r.view.Store(true)
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, &signed)); !errors.Is(err, ErrSpaceViewOnlyThere) {
		t.Errorf("«Только показ экрана»: %v", err)
	}
	r.view.Store(false)
	if len(r.asked()) != 0 || signed.Load() {
		t.Errorf("окон %d, состав отдан %v", len(r.asked()), signed.Load())
	}
}

// TestSpaceJoinOldVoucher — поручитель без join (≤ v0.3.1): без пароля — ErrSpaceNeedPass до отправки чего-либо
// (ни неудачи, ни соли); с паролем — прежний путь работает.
func TestSpaceJoinOldVoucher(t *testing.T) {
	r := admitHost(t, func(r *admitRig) { r.a.noJoin, r.a.SpaceAdmit = true, nil })
	d := r.joinDial(newKey(), nil, r.fresh(), nil, nil)
	var salted atomic.Bool
	d.OwnerKey = func([]byte) (ed25519.PrivateKey, error) { salted.Store(true); return nil, errors.New("тест") }
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceNeedPass) || salted.Load() {
		t.Errorf("старый поручитель без пароля: %v (соль %v)", err, salted.Load())
	}
	ownerLocks(t, r.a)
	d.Password = "secret123"
	if out, err := SpaceJoin(context.Background(), d); err != nil || string(out) != "M-SECRET-MARK-1+N" {
		t.Errorf("путь с паролем: %q %v", out, err)
	}
}

// TestSpaceJoinPasswordToNew — пароль ввели (запасной путь), поручитель новый: вход паролем и кодом, состав — только
// после «Разрешить»; в окне — заявленные ID и имя, новый член — только под этим ID; стадия «ждём «Разрешить»» видна.
func TestSpaceJoinPasswordToNew(t *testing.T) {
	r := admitHost(t)
	var stages []string
	d := r.joinDial(newKey(), nil, r.fresh(), &stages, nil)
	d.Password = "secret123"
	salted := false
	d.OwnerKey = func([]byte) (ed25519.PrivateKey, error) { salted = true; return nil, errors.New("тест") }
	if _, err := SpaceJoin(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	r.amu.Lock()
	jid := r.jid
	r.amu.Unlock()
	if a := r.asked(); len(a) != 1 || a[0].ID != "987654321" || a[0].Name != "Ноутбук" || jid != "987654321" || salted {
		t.Errorf("окно %+v, ID в SpaceJoin %q, путь без пароля %v", a, jid, salted)
	}
	if strings.Join(stages, ",") != "link,auth,list,admit" {
		t.Errorf("стадии %v", stages)
	}
}

// TestSpaceJoinLockedFallback — решение владельца C: лестница вступления по коду заперта — joinlocked; запасной путь с
// паролем проходит, но только после «Разрешить» (окно обязательно, ввод сессии на время окна выключен); неверный
// пароль — обычная лестница входа, лестница вступления не тронута; без пароля — по-прежнему joinlocked.
func TestSpaceJoinLockedFallback(t *testing.T) {
	r := admitHost(t, func(r *admitRig) { r.answer = no })
	r.a.mu.Lock()
	r.a.joinUntil = time.Now().Add(time.Hour)
	r.a.mu.Unlock()
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceJoinLocked) {
		t.Fatalf("заперто: %v", err)
	}
	var signed atomic.Bool
	pw := func(p string) SpaceDial {
		d := r.joinDial(newKey(), nil, r.fresh(), nil, &signed)
		d.Password = p
		return d
	}
	if _, err := SpaceJoin(context.Background(), pw("secret123")); !errors.Is(err, ErrSpaceDeclined) || signed.Load() || len(r.asked()) != 1 {
		t.Errorf("с паролем без «Разрешить»: %v, состав %v, окон %d", err, signed.Load(), len(r.asked()))
	}
	r.noPause()
	if _, err := SpaceJoin(context.Background(), pw("wrong-pass")); !errors.Is(err, ErrSpaceAuth) || len(r.asked()) != 1 {
		t.Errorf("неверный пароль: %v, окон %d", err, len(r.asked()))
	}
	if f, _ := lock(r.a); f != 1 {
		t.Errorf("неверный пароль не в лестнице входа: %d", f)
	}
	r.a.mu.Lock()
	jf, ju := r.a.joinFails, r.a.joinUntil
	r.a.mu.Unlock()
	if jf != 0 || time.Until(ju) < 59*time.Minute {
		t.Errorf("лестница вступления тронута: %d, %v", jf, time.Until(ju))
	}
	r.setAnswer(yes)
	if out, err := SpaceJoin(context.Background(), pw("secret123")); err != nil || string(out) != "M-SECRET-MARK-1+N" || len(r.asked()) != 2 {
		t.Errorf("с паролем и «Разрешить»: %q %v, окон %d", out, err, len(r.asked()))
	}
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceJoinLocked) {
		t.Errorf("без пароля после пути с паролем: %v", err)
	}
	r.a.mu.Lock()
	r.a.joinUntil = time.Time{}
	r.a.mu.Unlock()
}

// TestSpaceJoinPasswordAdmit — вход паролем (клиент ≤ v0.3.1) на новом поручителе: состав — только после «Разрешить»
// (окно без ID: старый клиент его не сообщает); на время окна ввод этой сессии выключен; «Отклонить» — отказ, состава
// N не видел; состав без запроса до «Разрешить» — отказ rights (окно старым протоколом не обойти).
func TestSpaceJoinPasswordAdmit(t *testing.T) {
	var blocked, after atomic.Int32
	r := admitHost(t)
	old := func(signed *atomic.Bool) SpaceDial {
		d := r.joinDial(newKey(), nil, r.fresh(), nil, signed)
		d.Password, d.Self, d.Name, d.OwnerKey = "secret123", "", "", nil
		return d
	}
	r.setAnswer(func(context.Context, AdmitReq) AdmitResult {
		r.a.mu.Lock()
		s := r.a.sess
		r.a.mu.Unlock()
		if s != nil && s.admitBlock.Load() && !s.inputOK() {
			blocked.Add(1)
		}
		return AdmitNo
	})
	var signed atomic.Bool
	d := old(&signed)
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceDeclined) || signed.Load() {
		t.Errorf("«Отклонить» при входе паролем: %v (состав %v)", err, signed.Load())
	}
	if a := r.asked(); len(a) != 1 || a[0].ID != "" || a[0].FP != pake.KeyFingerprint(d.Key.Public().(ed25519.PublicKey)) {
		t.Errorf("окно: %+v", a)
	}
	if blocked.Load() != 1 {
		t.Error("ввод сессии не выключен на время окна")
	}
	r.noPause()
	r.setAnswer(func(context.Context, AdmitReq) AdmitResult {
		r.a.mu.Lock()
		if s := r.a.sess; s != nil {
			time.AfterFunc(200*time.Millisecond, func() {
				if !s.admitBlock.Load() {
					after.Add(1)
				}
			})
		}
		r.a.mu.Unlock()
		return AdmitYes
	})
	if out, err := SpaceJoin(context.Background(), old(&signed)); err != nil || string(out) != "M-SECRET-MARK-1+N" || len(r.asked()) != 2 {
		t.Errorf("«Разрешить» при входе паролем: %q %v, окон %d", out, err, len(r.asked()))
	}
	time.Sleep(300 * time.Millisecond)
	if after.Load() != 1 {
		t.Error("ввод не вернулся после окна")
	}
	r.mu.Lock()
	r.joined = nil
	r.mu.Unlock()
	spEarlyM = []byte("M-SECRET-MARK-1+N")
	_, err := SpaceJoin(context.Background(), old(nil))
	spEarlyM = nil
	r.mu.Lock()
	joined := r.joined
	r.mu.Unlock()
	if !errors.Is(err, ErrSpaceRefused) || !strings.Contains(err.Error(), "rights") || joined != nil {
		t.Errorf("состав до «Разрешить»: %v, принят %q", err, joined)
	}
}

// TestInputOK — ввод сессии не идёт на хост, пока открыто окно «Пустить?» этой сессии.
func TestInputOK(t *testing.T) {
	var s session
	s.authed.Store(true)
	if !s.inputOK() {
		t.Fatal("управление без окна — ввод выключен")
	}
	s.admitBlock.Store(true)
	if s.inputOK() {
		t.Error("ввод идёт при открытом окне «Пустить?»")
	}
}

// TestSpaceJoinNotThere — поручитель сейчас не пускает: не в пространстве (none), «Спрашивать» (ask), сам ждёт
// сверки (LoginShut), занят другим сеансом (busy). Окна нет.
func TestSpaceJoinNotThere(t *testing.T) {
	r := admitHost(t)
	r.why.Store("none")
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceNotThere) {
		t.Errorf("не в пространстве: %v", err)
	}
	r.why.Store("ask")
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceAsk) {
		t.Errorf("«Спрашивать»: %v", err)
	}
	r.why.Store("")
	r.shut.Store(true)
	c := []byte(r.fresh()) // без верного кода посторонний не узнаёт, что поручитель недавно вступил
	c[0] = '0' + (c[0]-'0'+1)%10
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, string(c), nil, nil)); !errors.Is(err, ErrSpaceBadCode) {
		t.Errorf("поручитель ждёт сверки, неверный код: %v", err)
	}
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceWaitThere) {
		t.Errorf("поручитель ждёт сверки: %v", err)
	}
	r.shut.Store(false)
	r.a.mu.Lock()
	r.a.sess = &session{cid: "занят"}
	r.a.mu.Unlock()
	if _, err := SpaceJoin(context.Background(), r.joinDial(newKey(), nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceBusyThere) {
		t.Errorf("идёт сеанс: %v", err)
	}
	r.a.mu.Lock()
	r.a.sess = nil // Disconnect в конце теста шлёт «bye» сеансу — у поддельного нет хаба
	r.a.mu.Unlock()
	if len(r.asked()) != 0 {
		t.Errorf("окон %d", len(r.asked()))
	}
}

// TestSpaceJoinHostProof — код уходит только хосту, доказавшему ключ над этим соединением и (если он знаком) тому же
// ключу: подпись не над этим соединением — отказ без кода; другой отпечаток, чем запомненный, — ErrSpaceHostKey.
func TestSpaceJoinHostProof(t *testing.T) {
	r := admitHost(t)
	nkey := newKey()
	joinBadHostSig.Store(true)
	_, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil))
	joinBadHostSig.Store(false)
	if !errors.Is(err, ErrSpaceAuth) || r.codes.Load() != 0 {
		t.Errorf("подпись хоста не над этим соединением: %v, кодов у хоста %d", err, r.codes.Load())
	}
	d := r.joinDial(nkey, nil, r.fresh(), nil, nil)
	d.Known = "0000 0000 0000 0000 0000 0000 0000 0000"
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceHostKey) || r.codes.Load() != 0 {
		t.Errorf("чужой ключ хоста: %v, кодов у хоста %d", err, r.codes.Load())
	}
	d.Known = pake.KeyFingerprint(r.a.Key.Public().(ed25519.PublicKey))
	if _, err := SpaceJoin(context.Background(), d); err != nil || r.codes.Load() != 1 {
		t.Errorf("запомненный ключ: %v, кодов %d", err, r.codes.Load())
	}
}

// TestAdmitText — окно «Пустить?» на 7 языках: имя, ID тройками, отпечаток, срок 2 мин; без имени и без ID.
func TestAdmitText(t *testing.T) {
	q := AdmitReq{ID: "142226863", Name: "Ноутбук", FP: "ab12 cd34"}
	for _, lang := range []string{"en", "ru", "zh", "es", "de", "fr", "it"} {
		if _, ok := admitAsks[lang]; !ok {
			t.Fatalf("нет языка %s", lang)
		}
		title, text, yes, no, hint := admitText(lang, q, true)
		for _, s := range []string{"Ноутбук", "142 226 863", "ab12 cd34", "2 ", admitAsks[lang][11]} {
			if !strings.Contains(text, s) {
				t.Errorf("%s: нет %q в %q", lang, s, text)
			}
		}
		if title == "" || yes == "" || no == "" || hint == "" || yes == no {
			t.Errorf("%s: заголовок или кнопки пусты", lang)
		}
	}
	_, text, _, _, _ := admitText("ru", AdmitReq{FP: "ab12"}, false)
	if !strings.Contains(text, "без имени") || !strings.Contains(text, "ID не сообщён") || !strings.Contains(text, "3 секунды") {
		t.Errorf("без имени и ID: %q", text)
	}
}

// TestAdmitLoop — окна «Пустить?» без выключаемой кнопки: срок — на все окна (потом «нет ответа»), «Разрешить» раньше
// задержки — окно снова, «Отклонить» и «окна нет» — сразу, ctx кончился — отказ. Срок по решению владельца — 2 мин.
func TestAdmitLoop(t *testing.T) {
	defer func(w, d, s time.Duration) { admitWait, AskDelay, askSpawn = w, d, s }(admitWait, AskDelay, askSpawn)
	admitWait, AskDelay, askSpawn = 1500*time.Millisecond, 200*time.Millisecond, 0
	var first time.Duration
	t0 := time.Now()
	if r := admitLoop(context.Background(), func(left time.Duration, again bool) AdmitResult {
		if !again {
			first = left
		}
		time.Sleep(left)
		return AdmitNoAnswer
	}); r != AdmitNoAnswer || first > admitWait || first < admitWait-100*time.Millisecond || time.Since(t0) > 2500*time.Millisecond {
		t.Errorf("срок: %v, первое окно %v, всего %v", r, first, time.Since(t0))
	}
	shows := 0
	if r := admitLoop(context.Background(), func(time.Duration, bool) AdmitResult { shows++; return AdmitYes }); r != AdmitYes || shows < 2 {
		t.Errorf("ранний «Разрешить»: %v, окон %d", r, shows)
	}
	for _, want := range []AdmitResult{AdmitNo, AdmitNoWindow} {
		shows = 0
		if r := admitLoop(context.Background(), func(time.Duration, bool) AdmitResult { shows++; return want }); r != want || shows != 1 {
			t.Errorf("%v: %v, окон %d", want, r, shows)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := admitLoop(ctx, func(time.Duration, bool) AdmitResult { return AdmitYes }); r != AdmitNo {
		t.Errorf("ctx кончился: %v", r)
	}
	if AdmitTimeout != 2*time.Minute {
		t.Errorf("AdmitTimeout %v — решение владельца: до 2 мин", AdmitTimeout)
	}
}
