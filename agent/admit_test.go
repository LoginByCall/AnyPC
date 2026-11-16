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
// окно «Пустить?» — answer теста; asks — что показали в окне.
type admitRig struct {
	*spaceRig
	url    string
	owner  ed25519.PrivateKey
	osalt  []byte
	why    atomic.Value // string: ответ SpaceOwner ("" — пускает)
	amu    sync.Mutex
	asks   []AdmitReq
	answer func(AdmitReq) bool
	jid    string // id в SpaceJoin
}

func admitHost(t *testing.T, opt ...func(*admitRig)) *admitRig {
	t.Helper()
	url := local(t)
	_, owner, _ := ed25519.GenerateKey(nil)
	r := &admitRig{url: url, owner: owner, osalt: []byte("osalt-0123456789"), answer: func(AdmitReq) bool { return true }}
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
		s.a.SpaceAdmit = func(q AdmitReq) bool {
			r.amu.Lock()
			r.asks = append(r.asks, q)
			f := r.answer
			r.amu.Unlock()
			return f(q)
		}
		join := s.a.SpaceJoin
		s.a.SpaceJoin = func(sl, m []byte, pub ed25519.PublicKey, id string) error {
			r.amu.Lock()
			r.jid = id
			r.amu.Unlock()
			return join(sl, m, pub, id)
		}
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

// TestSpaceJoinAdmit — Ч12б, решения A' и B, happy-path: без пароля — код, доказательство фразы, окно «Пустить?» с
// ID, именем и отпечатком ключа N, «Разрешить» — P принимает M под показанным ID. Сессия вступления — не вход:
// плашки и видео нет. Код, ключ владельца и состав — не в журнале.
func TestSpaceJoinAdmit(t *testing.T) {
	var logs syncBuf
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	r := admitHost(t)
	_, nkey, _ := ed25519.GenerateKey(nil)
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
	if f, _ := lock(r.a); f != 0 {
		t.Errorf("неудач у P: %d", f)
	}
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

// TestSpaceJoinAdmitDeny — «Отклонить»: отказ declined, состава N не получил; повтор того же ключа или того же ID
// раньше admitEvery — later без окна; другой ID и ключ — окно; после admitEvery — снова окно.
func TestSpaceJoinAdmitDeny(t *testing.T) {
	defer func(e time.Duration) { admitEvery = e }(admitEvery)
	admitEvery = 1500 * time.Millisecond
	r := admitHost(t, func(r *admitRig) { r.answer = func(AdmitReq) bool { return false } })
	_, nkey, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	var signed atomic.Bool
	if _, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, &signed)); !errors.Is(err, ErrSpaceDeclined) || !errors.Is(err, ErrSpaceRefused) {
		t.Fatalf("«Отклонить»: %v", err)
	}
	if signed.Load() || len(r.asked()) != 1 {
		t.Fatalf("после «Отклонить» состав %v, окон %d", signed.Load(), len(r.asked()))
	}
	if _, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceLater) {
		t.Errorf("тот же ключ сразу: %v", err)
	}
	d := r.joinDial(other, nil, r.fresh(), nil, nil) // другой ключ, тот же ID
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceLater) {
		t.Errorf("тот же ID сразу: %v", err)
	}
	if n := len(r.asked()); n != 1 {
		t.Errorf("повторы показали окно: %d", n)
	}
	d = r.joinDial(other, nil, r.fresh(), nil, nil)
	d.Self = "111222333"
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceDeclined) || len(r.asked()) != 2 {
		t.Errorf("другой ID и ключ: %v, окон %d", err, len(r.asked()))
	}
	time.Sleep(admitEvery)
	if _, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceDeclined) || len(r.asked()) != 3 {
		t.Errorf("после admitEvery: %v, окон %d", err, len(r.asked()))
	}
	if f, _ := lock(r.a); f != 0 {
		t.Errorf("отказы окна — не неудачи входа, а у P %d", f)
	}
}

// TestSpaceJoinAdmitTimeout — окно без ответа весь срок: отказ noanswer (не declined).
func TestSpaceJoinAdmitTimeout(t *testing.T) {
	defer func(w time.Duration) { admitWait = w }(admitWait)
	admitWait = 800 * time.Millisecond
	r := admitHost(t, func(r *admitRig) {
		r.answer = func(AdmitReq) bool { time.Sleep(admitWait); return false }
	})
	_, nkey, _ := ed25519.GenerateKey(nil)
	_, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil))
	if !errors.Is(err, ErrSpaceNoAnswer) || errors.Is(err, ErrSpaceDeclined) {
		t.Errorf("нет ответа: %v", err)
	}
}

// TestSpaceJoinBadCode — неверный код: неудача входа, соль владельца не отдана (фразу не проверить), окна нет.
func TestSpaceJoinBadCode(t *testing.T) {
	r := admitHost(t)
	_, nkey, _ := ed25519.GenerateKey(nil)
	code := r.fresh()
	bad := "000000"
	if code == bad {
		bad = "111111"
	}
	d := r.joinDial(nkey, nil, bad, nil, nil)
	salted := false
	ok := d.OwnerKey
	d.OwnerKey = func(s []byte) (ed25519.PrivateKey, error) { salted = true; return ok(s) }
	_, err := SpaceJoin(context.Background(), d)
	if !errors.Is(err, ErrSpaceBadCode) || !errors.Is(err, ErrSpaceAuth) {
		t.Errorf("неверный код: %v", err)
	}
	if salted || len(r.asked()) != 0 {
		t.Errorf("соль отдана %v, окон %d", salted, len(r.asked()))
	}
	if f, _ := lock(r.a); f != 1 {
		t.Errorf("неудач у P %d, ждали 1", f)
	}
}

// TestSpaceJoinBadPhrase — ключ не из той фразы: неудача входа без окна; пятая подряд запирает вход (как пароль).
func TestSpaceJoinBadPhrase(t *testing.T) {
	r := admitHost(t)
	_, nkey, _ := ed25519.GenerateKey(nil)
	_, wrong, _ := ed25519.GenerateKey(nil)
	for i := 1; i <= 5; i++ {
		_, err := SpaceJoin(context.Background(), r.joinDial(nkey, wrong, r.fresh(), nil, nil))
		if !errors.Is(err, ErrSpaceBadPhrase) || !errors.Is(err, ErrSpaceAuth) {
			t.Fatalf("попытка %d: %v", i, err)
		}
		if f, _ := lock(r.a); f != i {
			t.Fatalf("после %d неудач у P %d", i, f)
		}
	}
	if len(r.asked()) != 0 {
		t.Errorf("окно после неверной фразы: %d", len(r.asked()))
	}
	_, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil)) // и с верной — заперто
	if !errors.Is(err, ErrSpaceLockedThere) {
		t.Errorf("после 5 неудач: %v", err)
	}
}

// TestSpaceJoinProofTransfer — доказательство из другого соединения (те же P, ключ N и фраза, другие DTLS-отпечатки)
// не принимается; подпись ключом владельца в чужом домене (подпись клиента, хоста) — тоже.
func TestSpaceJoinProofTransfer(t *testing.T) {
	r := admitHost(t)
	_, nkey, _ := ed25519.GenerateKey(nil)
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

// TestSpaceJoinOldVoucher — поручитель без join (≤ v0.3.1): без пароля — ErrSpaceNeedPass до отправки чего-либо
// (ни неудачи, ни соли); с паролем — прежний путь работает.
func TestSpaceJoinOldVoucher(t *testing.T) {
	r := admitHost(t, func(r *admitRig) { r.a.noJoin, r.a.SpaceAdmit = true, nil })
	_, nkey, _ := ed25519.GenerateKey(nil)
	d := r.joinDial(nkey, nil, r.fresh(), nil, nil)
	salted := false
	d.OwnerKey = func([]byte) (ed25519.PrivateKey, error) { salted = true; return nil, errors.New("тест") }
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceNeedPass) || salted {
		t.Errorf("старый поручитель без пароля: %v (соль %v)", err, salted)
	}
	if f, _ := lock(r.a); f != 0 {
		t.Errorf("неудач у P %d", f)
	}
	d.Password = "secret123"
	if out, err := SpaceJoin(context.Background(), d); err != nil || string(out) != "M-SECRET-MARK-1+N" {
		t.Errorf("путь с паролем: %q %v", out, err)
	}
}

// TestSpaceJoinPasswordAdmit — вход паролем (клиент ≤ v0.3.1) на новом поручителе: состав — только после «Разрешить»
// (окно без ID: старый клиент его не сообщает); «Отклонить» — отказ, состава N не видел.
func TestSpaceJoinPasswordAdmit(t *testing.T) {
	var answer atomic.Bool
	r := admitHost(t, func(r *admitRig) { r.answer = func(AdmitReq) bool { return answer.Load() } })
	_, nkey, _ := ed25519.GenerateKey(nil)
	var signed atomic.Bool
	d := r.joinDial(nkey, nil, r.fresh(), nil, &signed)
	d.Password, d.Self, d.Name = "secret123", "", ""
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceDeclined) || signed.Load() {
		t.Errorf("«Отклонить» при входе паролем: %v (состав %v)", err, signed.Load())
	}
	if a := r.asked(); len(a) != 1 || a[0].ID != "" || a[0].FP != pake.KeyFingerprint(nkey.Public().(ed25519.PublicKey)) {
		t.Errorf("окно: %+v", a)
	}
	answer.Store(true)
	_, nkey2, _ := ed25519.GenerateKey(nil) // другой ключ — мимо admitEvery
	d = r.joinDial(nkey2, nil, r.fresh(), nil, &signed)
	d.Password, d.Self, d.Name = "secret123", "", ""
	if out, err := SpaceJoin(context.Background(), d); err != nil || string(out) != "M-SECRET-MARK-1+N" || len(r.asked()) != 2 {
		t.Errorf("«Разрешить» при входе паролем: %q %v, окон %d", out, err, len(r.asked()))
	}
}

// TestSpaceJoinNotThere — поручитель сейчас не пускает: не в пространстве (none), «Спрашивать» (ask), сам ждёт
// сверки (LoginShut), занят другим сеансом (busy). Окна нет.
func TestSpaceJoinNotThere(t *testing.T) {
	r := admitHost(t)
	_, nkey, _ := ed25519.GenerateKey(nil)
	r.why.Store("none")
	if _, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceNotThere) {
		t.Errorf("не в пространстве: %v", err)
	}
	r.why.Store("ask")
	if _, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceAsk) {
		t.Errorf("«Спрашивать»: %v", err)
	}
	r.why.Store("")
	r.a.LoginShut = func(string) bool { return true }
	if _, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceWaitThere) {
		t.Errorf("поручитель ждёт сверки: %v", err)
	}
	r.a.LoginShut = nil
	r.a.mu.Lock()
	r.a.sess = &session{cid: "занят"}
	r.a.mu.Unlock()
	if _, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceBusyThere) {
		t.Errorf("идёт сеанс: %v", err)
	}
	r.a.mu.Lock()
	r.a.sess = nil // Disconnect в конце теста шлёт «bye» сеансу — у поддельного нет хаба
	r.a.mu.Unlock()
	if len(r.asked()) != 0 {
		t.Errorf("окон %d", len(r.asked()))
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

// TestAskLoopFor — срок окна askLoopFor — свой (окно «Пустить?» — AdmitTimeout, не AskTimeout).
func TestAskLoopFor(t *testing.T) {
	var first time.Duration
	t0 := time.Now()
	a := askLoopFor(1500*time.Millisecond, func(left time.Duration, again bool) Answer {
		if !again {
			first = left
		}
		time.Sleep(left)
		return Deny
	})
	if a != Deny || first > 1500*time.Millisecond || first < 1400*time.Millisecond || time.Since(t0) > 2500*time.Millisecond {
		t.Errorf("askLoopFor: %v, первое окно %v, всего %v", a, first, time.Since(t0))
	}
	if AdmitTimeout != 2*time.Minute {
		t.Errorf("AdmitTimeout %v — решение владельца: до 2 мин", AdmitTimeout)
	}
}

// TestSpaceJoinHostProof — код уходит только хосту, доказавшему ключ над этим соединением и (если он знаком) тому же
// ключу: подпись не над этим соединением — отказ без кода; другой отпечаток, чем запомненный, — ErrSpaceHostKey.
func TestSpaceJoinHostProof(t *testing.T) {
	r := admitHost(t)
	var codes atomic.Int32
	own := r.a.OTP
	r.a.OTP = func(u, c string) (bool, bool) { codes.Add(1); return own(u, c) }
	_, nkey, _ := ed25519.GenerateKey(nil)
	joinBadHostSig.Store(true)
	_, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil))
	joinBadHostSig.Store(false)
	if !errors.Is(err, ErrSpaceAuth) || codes.Load() != 0 {
		t.Errorf("подпись хоста не над этим соединением: %v, кодов у хоста %d", err, codes.Load())
	}
	d := r.joinDial(nkey, nil, r.fresh(), nil, nil)
	d.Known = "0000 0000 0000 0000 0000 0000 0000 0000"
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceHostKey) || codes.Load() != 0 {
		t.Errorf("чужой ключ хоста: %v, кодов у хоста %d", err, codes.Load())
	}
	d.Known = pake.KeyFingerprint(r.a.Key.Public().(ed25519.PublicKey))
	if _, err := SpaceJoin(context.Background(), d); err != nil || codes.Load() != 1 {
		t.Errorf("запомненный ключ: %v, кодов %d", err, codes.Load())
	}
}

// TestSpaceJoinCodeLocked — лестница кодов заперта (неверные коды записи или хоста), а паролей — нет: вступление и с
// верным кодом — locked, окна нет (проверка под тем же a.mu, что счёт: параллельные попытки не проскочат).
func TestSpaceJoinCodeLocked(t *testing.T) {
	r := admitHost(t)
	_, nkey, _ := ed25519.GenerateKey(nil)
	r.a.mu.Lock()
	r.a.nameOf("", true).otpUntil = time.Now().Add(time.Minute)
	r.a.mu.Unlock()
	if _, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceLockedThere) {
		t.Errorf("заперты коды записи: %v", err)
	}
	r.a.mu.Lock()
	r.a.names = nil
	r.a.otpLock = time.Now().Add(time.Minute)
	r.a.mu.Unlock()
	if _, err := SpaceJoin(context.Background(), r.joinDial(nkey, nil, r.fresh(), nil, nil)); !errors.Is(err, ErrSpaceLockedThere) {
		t.Errorf("заперты коды хоста: %v", err)
	}
	if len(r.asked()) != 0 {
		t.Errorf("окон %d", len(r.asked()))
	}
}
