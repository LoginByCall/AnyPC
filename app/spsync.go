package main

// «Моё пространство», этап Э4 + решение 10 A (2P-Set): члены сходятся к одному объединению M (UI-REDESIGN.md,
// «Сверка», «Исключение»). Сеть — agent/spsync.go; здесь хранение верхушек, приём, рассылка и правки состава для
// окна. ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md A13: ключевой материал).
//
// Хранение: settings.Space — главная верхушка (spaceHeads, первая), settings.SpaceHeads — остальные; всё — байты
// marshal(). Состав для решений — объединение (spaceLocked → spaceView). Приём (SyncApply) — любые подлинные M того же
// пространства (закреплённые sid, opub, osalt): они добавляются к верхушкам, перекрытые забываются. Расколов, флагов
// раскола и слияния нет: объединение одинаково на всех ПК, которые видели одни и те же M. Догоняние (SyncOffer) — в
// обмене сверки обе стороны отдают все свои верхушки: каждая M — полный состав, предки ничего не добавляют к
// объединению (потомок перекрывает предка, spaceUnder).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"anypc/agent"
	"anypc/pake"
	"anypc/totp"
)

var (
	errSpaceVia  = errors.New("пространство: пароль, код и «Спрашивать» этого ПК меняются через пространство (фраза)")
	errSpaceSelf = errors.New("пространство: этот ПК исключается с другого ПК пространства")
)

// spaceChanged — вход записи по умолчанию сменился (правка или приём M): сессии со старым паролем рвать
// (agent.DropRevoked).
var spaceChanged func()

// spaceStoredLocked — сохранённые верхушки (под c.mu): главная, затем остальные. Хоть одна не читается — ошибка
// (закрыто: пропустив испорченную верхушку, забыли бы её исключения — исключённый снова член).
func (c *config) spaceStoredLocked() ([]*space, error) {
	var out []*space
	for i, b := range slices.Concat([][]byte{c.Space}, c.SpaceHeads) {
		m, err := spaceParse(b)
		if err != nil {
			return nil, fmt.Errorf("верхушка %d: %w", i, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// spacePendLocked — непринятые M (под c.mu); не читается хоть одна — ошибка (закрыто, как spaceStoredLocked).
func (c *config) spacePendLocked() ([]*space, error) {
	var out []*space
	for i, b := range c.SpacePend {
		m, err := spaceParse(b)
		if err != nil {
			return nil, fmt.Errorf("непринятая правка %d: %w", i, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// spaceSnapLocked — байты состояния (верхушки и непринятые M): правка сверяет, что оно не сменилось.
func (c *config) spaceSnapLocked() []byte {
	var b []byte
	for _, x := range slices.Concat([][]byte{c.Space}, c.SpaceHeads, [][]byte{nil}, c.SpacePend) {
		b = append(append(b, byte(len(x)>>8), byte(len(x))), x...)
	}
	return b
}

// spaceAddLocked — добавить подлинные M к верхушкам (под c.mu, без save): чужое пространство — errSpaceForeign
// (ничего не принято). Вход объединения повторяется в записи по умолчанию (её Trusted/KeyLogin сбрасываются: пароль
// сменился; гостей не трогаем). changed — верхушки сменились; drop — вход записи по умолчанию сменился. Верхушек
// больше spaceMaxHeads и после поглощения перекрытых — errSpaceHeads: в верхушки ничего не принято, пришедшие M — в
// SpacePend (в составе для решений: исключения действуют сразу), SpaceOver закрывает ПК (spaceOwnerLocked), пока
// SpacePend не принят вместе с верхушками — правкой фразой здесь или сводящей правкой, пришедшей сверкой.
func (c *config) spaceAddLocked(in ...*space) (changed, drop bool, err error) {
	if len(c.Space) == 0 {
		return false, false, errSpaceNotIn
	}
	cur, err := c.spaceStoredLocked()
	if err != nil {
		return false, false, err
	}
	for _, m := range in {
		if m == nil || !cur[0].sameSpace(m) {
			return false, false, errSpaceForeign
		}
	}
	pend, err := c.spacePendLocked()
	if err != nil {
		return false, false, err
	}
	heads, err := spaceHeads(slices.Concat(cur, in, pend))
	if errors.Is(err, errSpaceHeads) {
		for _, m := range in { // только новое: M, равные своим верхушкам и непринятым или перекрытые ими, — мимо
			known := func(h *space) bool { return spaceUnder(m, h) }
			if slices.ContainsFunc(cur, known) || slices.ContainsFunc(pend, known) || len(c.SpacePend) >= spaceMaxPend {
				continue
			}
			if b, merr := m.marshal(); merr == nil {
				c.SpacePend, pend = append(c.SpacePend, b), append(pend, m)
			}
		}
		if c.SpaceOver == "" {
			c.SpaceOver = time.Now().UTC().Format(time.RFC3339) + " " + err.Error()
			log.Printf("%v — правка не принята в верхушки, пропусков нет до правки фразой на этом ПК или сводящей правки", err)
		}
		return false, c.spaceFollowLocked(), err
	}
	if err != nil {
		return false, false, err
	}
	var bs [][]byte
	for _, h := range heads {
		b, err := h.marshal()
		if err != nil {
			return false, false, err
		}
		bs = append(bs, b)
	}
	before := c.spaceSnapLocked()
	c.Space, c.SpaceHeads, c.SpacePend, c.SpaceOver = bs[0], bs[1:], nil, "" // непринятые приняты (или перекрыты)
	if len(c.SpaceHeads) == 0 {
		c.SpaceHeads = nil
	}
	if bytes.Equal(before, c.spaceSnapLocked()) {
		return false, false, nil
	}
	c.spaceWaitLocked()
	return true, c.spaceFollowLocked(), nil
}

// spaceWaitLocked — правило вступления (решение 12 A) на каждом изменении объединения: членов, кроме себя и
// поручителя, нет (остальных исключили) — сверять не с кем, SpaceWait снимается. Дефолт A вопроса владельцу.
func (c *config) spaceWaitLocked() {
	if m := c.spaceLocked(); c.SpaceWait != "" && m != nil &&
		!slices.ContainsFunc(m.Members, func(x spaceMember) bool { return x.ID != c.ID && x.ID != c.SpaceWait }) {
		c.SpaceWait = ""
	}
}

// spaceFollowLocked — вход состава (объединения) повторяется в записи по умолчанию (под c.mu): сменился — true.
func (c *config) spaceFollowLocked() bool {
	v := c.spaceLocked()
	if v == nil {
		return false
	}
	u := &c.Users[0]
	drop := !bytes.Equal(u.Salt, v.PSalt) || !bytes.Equal(u.Hash, v.PHash) || u.TOTP != v.TOTP
	if drop {
		if u.TOTP != v.TOTP {
			u.TOTPStep = 0
		}
		u.Salt, u.Hash, u.TOTP, u.Trusted, u.KeyLogin = bytes.Clone(v.PSalt), bytes.Clone(v.PHash), v.TOTP, nil, nil
	}
	return drop
}

// SyncGate — agent.SpaceSyncer: главная верхушка этого ПК ключу pub члена (объединения), если peer — подлинный M
// того же пространства (peer nil — без него).
func (c *config) SyncGate(pub ed25519.PublicKey, peer []byte) []byte {
	var p *space
	if peer != nil {
		var err error
		if p, err = spaceParse(peer); err != nil {
			return nil
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if cur := c.spaceLocked(); cur == nil || p != nil && !cur.sameSpace(p) {
		return nil
	}
	if !c.syncMemberLocked(pub) {
		return nil
	}
	return bytes.Clone(c.Space)
}

// syncMemberLocked — pub — член объединения (значит, не исключён ни в одной известной M) и не этот ПК.
func (c *config) syncMemberLocked(pub ed25519.PublicKey) bool {
	cur := c.spaceLocked()
	return cur != nil && !cur.gone(pub) && cur.member(pub) && !bytes.Equal(pub, ed25519.PrivateKey(c.Key).Public().(ed25519.PublicKey))
}

// SyncRecs — agent.SpaceSyncer: остальные верхушки этого ПК (кроме главной, она идёт в "m", и кроме peer).
func (c *config) SyncRecs(peer []byte) [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	var out [][]byte
	for _, b := range c.SpaceHeads {
		if !bytes.Equal(b, peer) {
			out = append(out, bytes.Clone(b))
		}
	}
	return out
}

// SyncApply — agent.SpaceSyncer: принять верхушки другого члена (recs и peer); вернуть свою главную после.
func (c *config) SyncApply(peer []byte, recs [][]byte) []byte {
	if err := c.spaceSync(peer, recs); err != nil {
		log.Printf("пространство: сверка: %v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.Space)
}

// spaceSync — добавить подлинные M (pb и rb) к верхушкам; новое — дальше остальным членам.
func (c *config) spaceSync(pb []byte, rb [][]byte) error {
	var in []*space
	for _, b := range append([][]byte{pb}, rb...) {
		m, err := spaceParse(b)
		if err != nil {
			return err
		}
		in = append(in, m)
	}
	c.mu.Lock()
	c.reload()
	snap := c.spaceSnapLocked()
	changed, drop, err := c.spaceAddLocked(in...)
	if changed || drop || !bytes.Equal(snap, c.spaceSnapLocked()) {
		if serr := c.save(); serr != nil && err == nil {
			err = serr
		}
		if v := c.spaceLocked(); v != nil && v.Compromised {
			log.Print("пространство: секрет кода видел исключённый ПК — пропусков нет до нового кода (фраза)")
		}
	}
	c.mu.Unlock()
	if (drop || changed) && spaceChanged != nil { // и без смены входа: новое исключение меняет loginTag
		spaceChanged()
	}
	if s := c.syn; s != nil && changed { // принятое — дальше остальным
		s.bg.Go(func() { s.spread(s.bgCtx(), true) })
	}
	return err
}

// spaceResult — итог сверки с одним членом: State — "ok" (главные верхушки сошлись) | "differs" | "offline" |
// "old" (версия без сверки) | "badid" (под ID ответил чужой ключ, С4; ответ не подписан — только для окна) |
// "clock" (часы расходятся больше 10 мин; тоже не подписано) | "refused".
type spaceResult struct {
	ID    string
	State string
	Err   error
}

// spaceSyncer — рассылка состава этого ПК членам с повтором (как offRetry: пауза растёт до spaceSyncRetryMax, всего
// не дольше spaceSyncRetryFor; дальше — периодическая сверка).
type spaceSyncer struct {
	cfg   *config
	ctx   context.Context // фоновые повторы — до его конца
	mu    sync.Mutex
	retry map[string]*int // ID → метка своего повтора: новая рассылка заменяет старый повтор
	bg    sync.WaitGroup
}

// Сеть (agent/spsync.go) и паузы повтора; переменные — для теста.
var (
	spaceSyncFn                       = agent.SpaceSync
	spaceSyncRetry, spaceSyncRetryMax = time.Second, 5 * time.Minute
	spaceSyncRetryFor                 = time.Hour
)

func (s *spaceSyncer) bgCtx() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

// one — сверка с членом x. Состояние меняют только подписанные итоги: "ok" (подписанный M хоста равен своему)
// снимает SpaceWait, если x — не поручитель. "badid" и "clock" приходят без подписи (их может подставить хаб) — на
// решения не влияют; "clock" — в SpaceClock для окна.
func (s *spaceSyncer) one(ctx context.Context, x spaceMember) spaceResult {
	c := s.cfg
	hostM, err := spaceSyncFn(ctx, agent.SyncDial{Server: c.server(), ID: x.ID, HostPub: x.Pub, Key: c.key(), S: c})
	r := spaceResult{ID: x.ID, State: "refused", Err: err}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	switch {
	case err == nil && bytes.Equal(hostM, c.Space) && spaceSigned(hostM): // подтверждение — подписанный M хоста, тот же
		r.State = "ok"
	case err == nil:
		r.State = "differs"
	case errors.Is(err, agent.ErrSpaceOffline):
		r.State = "offline"
	case errors.Is(err, agent.ErrSpaceOld):
		r.State = "old"
	case errors.Is(err, agent.ErrSpaceIDKey):
		r.State = "badid"
		log.Printf("пространство: под ID %s ответил не тот ПК (ответ не подписан — возможно, подмена хабом)", x.ID)
	case errors.Is(err, agent.ErrSpaceSkew):
		r.State = "clock"
	}
	clock, ch := slices.Contains(c.SpaceClock, x.ID), false
	switch {
	case r.State == "clock" && !clock:
		c.SpaceClock, ch = append(c.SpaceClock, x.ID), true
	case (r.State == "ok" || r.State == "differs") && clock: // обмен прошёл — часы сошлись
		c.SpaceClock, ch = slices.DeleteFunc(c.SpaceClock, func(id string) bool { return id == x.ID }), true
	}
	if r.State == "ok" && c.SpaceWait != "" && c.SpaceWait != x.ID {
		c.SpaceWait, ch = "", true
	}
	if ch {
		c.save()
	}
	return r
}

// spread — сверка со всеми членами объединения, кроме себя, параллельно; retry — не дошедшее повторять в фоне до
// подтверждения, исключения цели, ответа старой версии, spaceSyncRetryFor или конца s.ctx.
func (s *spaceSyncer) spread(ctx context.Context, retry bool) []spaceResult {
	targets := s.cfg.spaceOthers()
	out := make([]spaceResult, len(targets))
	var wg sync.WaitGroup
	for i, x := range targets {
		wg.Go(func() {
			out[i] = s.one(ctx, x)
			if retry && out[i].State != "ok" && out[i].State != "old" {
				s.later(x)
			}
		})
	}
	wg.Wait()
	return out
}

// spaceOthers — члены объединения, кроме этого ПК.
func (c *config) spaceOthers() []spaceMember {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	m := c.spaceLocked()
	if m == nil {
		return nil
	}
	self := ed25519.PrivateKey(c.Key).Public().(ed25519.PublicKey)
	return slices.DeleteFunc(slices.Clone(m.Members), func(x spaceMember) bool { return bytes.Equal(x.Pub, self) })
}

func (s *spaceSyncer) later(x spaceMember) {
	tok := new(int)
	s.mu.Lock()
	if s.retry == nil {
		s.retry = map[string]*int{}
	}
	s.retry[x.ID] = tok
	s.mu.Unlock()
	ctx := s.bgCtx()
	end := time.Now().Add(spaceSyncRetryFor)
	s.bg.Go(func() {
		defer func() {
			s.mu.Lock()
			if s.retry[x.ID] == tok {
				delete(s.retry, x.ID)
			}
			s.mu.Unlock()
		}()
		for wait := spaceSyncRetry; ; wait = min(2*wait, spaceSyncRetryMax) {
			if time.Now().Add(wait).After(end) {
				return // дальше — периодическая сверка (spaceEvery) и сверка при запуске
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(syncJitter(wait)):
			}
			s.mu.Lock()
			mine := s.retry[x.ID] == tok
			s.mu.Unlock()
			if c := s.cfg; !mine || c.SyncGate(x.Pub, nil) == nil { // заменён новой рассылкой или больше не член
				return
			}
			if r := s.one(ctx, x); r.State == "ok" || r.State == "old" {
				return
			}
		}
	})
}

// spaceFresh — сразу после вступления (п. 5 Э4): сверка с остальными членами; fresh — пропуска выдаются (сверен с
// членом, кроме P, или других нет). P сверяется с остальными до выдачи M (spaceGet) и до ответа (spaceJoin).
func (c *config) spaceFresh(ctx context.Context) bool {
	if c.syn != nil {
		c.syn.spread(ctx, true)
	}
	return c.spaceFreshNow()
}

func (c *config) spaceFreshNow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.SpaceWait == ""
}

// spaceEdit — сохранить правку n объединения со снимком snap (если состояние не сменилось за время правки). Правка
// объединения со скомпрометированным входом без нового секрета кода — отказ.
func (c *config) spaceEdit(snap []byte, n *space) (bool, error) {
	c.mu.Lock()
	c.reload()
	if !bytes.Equal(c.spaceSnapLocked(), snap) {
		c.mu.Unlock()
		return false, errSpaceChange
	}
	if v := c.spaceLocked(); v != nil && v.Compromised && n.TOTP == v.TOTP {
		c.mu.Unlock()
		return false, errSpaceCompromised
	}
	_, drop, err := c.spaceAddLocked(n)
	if err == nil {
		err = c.save()
	}
	c.mu.Unlock()
	if err == nil && drop && spaceChanged != nil {
		spaceChanged()
	}
	return drop, err
}

// edit — правка состава фразой (f — правило ядра) от объединения, с рассылкой: сперва сверка со всеми доступными
// (правка — от свежего объединения), затем f над ним.
func (s *spaceSyncer) edit(ctx context.Context, f func(m *space) (*space, error)) ([]spaceResult, error) {
	c := s.cfg
	s.spread(ctx, false)
	c.mu.Lock()
	c.reload()
	m, snap, bad := c.spaceLocked(), c.spaceSnapLocked(), c.spaceDamagedLocked()
	c.mu.Unlock()
	if bad {
		return nil, errSpaceDamaged
	}
	if m == nil {
		return nil, errSpaceNotIn
	}
	n, err := f(m) // Argon2 фразы — без c.mu
	if err != nil {
		return nil, err
	}
	if _, err := c.spaceEdit(snap, n); err != nil {
		return nil, err
	}
	return s.spread(ctx, true), nil
}

// spaceExclude — исключить ПК pub (украденный) с этого ПК: новый секрет кода и, если newPassword не "", новый пароль
// входа одной правкой (решение 5 владельца); итог рассылки по целям.
func (s *spaceSyncer) spaceExclude(ctx context.Context, phrase string, pub ed25519.PublicKey, newPassword string) ([]spaceResult, error) {
	if bytes.Equal(pub, s.cfg.key().Public().(ed25519.PublicKey)) {
		return nil, errSpaceSelf
	}
	if newPassword != "" && len([]rune(newPassword)) < 8 {
		return nil, errors.New("пароль короче 8 символов")
	}
	return s.edit(ctx, func(m *space) (*space, error) { return spaceRemoveLogin(m, phrase, pub, newPassword) })
}

// spaceChangeLogin — новый вход пространства (запись по умолчанию на всех членах): новый пароль (newPassword; ""
// — прежний) и, если newCode или вход скомпрометирован, новый секрет кода (окно покажет новый QR).
func (s *spaceSyncer) spaceChangeLogin(ctx context.Context, phrase, newPassword string, newCode bool) ([]spaceResult, error) {
	if newPassword != "" && len([]rune(newPassword)) < 8 {
		return nil, errors.New("пароль короче 8 символов")
	}
	return s.edit(ctx, func(m *space) (*space, error) {
		sec := ""
		if newCode || m.Compromised {
			sec = totp.NewSecret()
		}
		return spaceSetLogin(m, phrase, newPassword, sec)
	})
}

// startSpaceSync — при запуске: рассылка правок с этого ПК, сверка со всеми членами (ПК мог пропустить правки, пока
// был выключен); вход сменился — рвать сессии со старым паролем.
func startSpaceSync(ctx context.Context, cfg *config, a *agent.Agent) {
	cfg.syn = &spaceSyncer{cfg: cfg, ctx: ctx}
	spaceChanged = a.DropRevoked
	cfg.syn.bg.Go(func() {
		cfg.syn.spread(ctx, true)
		for { // раз в spaceEvery — со случайным членом, пока есть пространство (правки, до которых не дошла рассылка)
			select {
			case <-ctx.Done():
				return
			case <-time.After(syncJitter(spaceEvery)):
			}
			cfg.syn.random(ctx)
		}
	})
}

// spaceEvery — пауза периодической сверки.
var spaceEvery = 10 * time.Minute

// random — сверка с одним случайным членом, кроме себя.
func (s *spaceSyncer) random(ctx context.Context) {
	if l := s.cfg.spaceOthers(); len(l) > 0 {
		s.one(ctx, l[rand.IntN(len(l))])
	}
}

// spaceSigned — b — целая запись M с верной подписью (кем подписан — сверяет вызывающий сравнением со своим).
func spaceSigned(b []byte) bool { _, err := spaceParse(b); return err == nil }

// loginTag — agent.Agent.LoginTag: метка входа записи по умолчанию — хэш её соли, хэша пароля и секрета TOTP (в
// пространстве это вход объединения, spaceFollowLocked): смена пароля или кода — новая метка, и при выходе из
// пространства и повторном вступлении с другим кодом тоже. Клиенту — член объединения с доказанным ключом — только
// она; клиенту без ключа или не члену (может быть любым ПК) — ещё число исключённых, если они есть: новое
// исключение рвёт такую сессию. Записи состава не читаются — метка от их
// байт (одна на испорченное состояние: сессии рвутся один раз, не циклом опроса). Гости и режим «Спрашивать» (вход
// одноразовым кодом) — nil. Ключ исключённого ПК рвёт сессию отдельно (keyGone, любой режим и запись).
func (c *config) loginTag(user string, cpub []byte) []byte {
	if user != "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if c.codeModeLocked() {
		return nil
	}
	u := c.Users[0]
	b := []byte("anypc-login-tag\x00")
	for _, x := range [][]byte{u.Salt, u.Hash, []byte(u.TOTP)} {
		b = append(binary.BigEndian.AppendUint16(b, uint16(len(x))), x...)
	}
	base := sha256.Sum256(b)
	if len(c.Space) == 0 {
		return base[:]
	}
	m := c.spaceLocked()
	switch {
	case m == nil:
		h := sha256.Sum256(append([]byte("anypc-space-damaged\x00"), c.spaceSnapLocked()...))
		return h[:]
	case cpub != nil && m.member(cpub), len(m.Gone) == 0:
		return base[:]
	}
	h := sha256.Sum256(binary.BigEndian.AppendUint16(base[:], uint16(len(m.Gone))))
	return h[:]
}

// keyGone — agent.Agent.KeyGone: ключ pub исключён в объединении этого ПК (решение владельца A).
func (c *config) keyGone(pub []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	m := c.spaceLocked()
	return m != nil && m.gone(pub)
}

// loginShut — agent.Agent.LoginShut (решение 12 A): вход паролем в запись по умолчанию закрыт, пока ПК, вступивший
// в пространство, не сверился с членом ≠ поручитель (SpaceWait). «Спрашивать» (одноразовый код) и гости — открыты.
// ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (A13: вход).
func (c *config) loginShut(user string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	return user == "" && c.SpaceWait != "" && len(c.Space) > 0 && !c.codeModeLocked()
}

// spaceDamaged — записи состава есть, но не читаются (для окна: «выйти и вступить снова»).
func (c *config) spaceDamaged() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	return c.spaceDamagedLocked()
}

func (c *config) spaceDamagedLocked() bool { return len(c.Space) > 0 && c.spaceLocked() == nil }

// SyncKey — agent.SpaceSyncer: pub — член объединения этого ПК (не исключён ни в одной известной M) и не свой.
func (c *config) SyncKey(pub ed25519.PublicKey) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	return c.syncMemberLocked(pub)
}

// spaceLeave — выйти из пространства на этом ПК без фразы (С6: иначе пароль и код записи по умолчанию не сменить):
// пароль записи по умолчанию и верный код TOTP. Удаляются верхушки и флаги; запись по умолчанию остаётся с теми же
// паролем и кодом (до сверки после вступления — без пароля и кода, решение 12 A: они из M поручителя); пропуска,
// выданные здесь, гаснут (DropRevoked), выданные этому ПК как мастеру — снимаются.
func (c *config) spaceLeave(password, code string) error {
	c.mu.Lock()
	c.reload()
	in, salt, hash := len(c.Space) > 0, bytes.Clone(c.Users[0].Salt), bytes.Clone(c.Users[0].Hash)
	c.mu.Unlock()
	if !in {
		return errSpaceNotIn
	}
	if len(hash) == 0 || subtle.ConstantTimeCompare(pake.KDF(password, salt), hash) != 1 { // Argon2 — без c.mu
		return errSpacePassword
	}
	c.mu.Lock()
	c.reload()
	u := &c.Users[0]
	if !bytes.Equal(u.Salt, salt) {
		c.mu.Unlock()
		return errSpaceChange
	}
	step, ok := totp.Check(u.TOTP, code, time.Now(), u.TOTPStep)
	if !ok {
		c.mu.Unlock()
		return errPassCode
	}
	u.TOTPStep = step
	if c.SpaceWait != "" { // решение 12 A: пароль и код — из M поручителя, сверкой не подтверждённого: не оставлять
		on := true // вход — «Спрашивать» с новым одноразовым кодом с экрана (как setConfirm), окно попросит пароль
		u.Salt, u.Hash, u.TOTP, u.TOTPStep, c.Confirm = nil, nil, "", 0, &on
		c.setCode(randCode())
	}
	c.Space, c.SpaceHeads, c.SpaceWait, c.SpaceClock, c.SpaceOver, c.SpacePend = nil, nil, "", nil, "", nil
	err := c.save()
	c.mu.Unlock()
	if err != nil {
		return err
	}
	log.Print("пространство: этот ПК вышел из пространства")
	if spaceChanged != nil {
		spaceChanged()
	}
	if passes.cfg == c {
		passes.offAll(context.Background())
	}
	return nil
}
