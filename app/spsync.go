package main

// «Моё пространство», этап Э4: члены держат одинаковый M (UI-REDESIGN.md, «Сверка», «Исключение»). Сеть —
// agent/spsync.go; здесь цепочка, приём, раскол, рассылка и правки состава для окна. ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ
// (CLAUDE.md A13: ключевой материал).
//
// Цепочка (settings.SpaceLog) — записи M, на которых менялся вход (lgen), последние spaceLogMax: ПК, пропустивший
// несколько смен входа, принимает их по порядку (spaceAccept требует прямого продолжения входа), а не раскол.
// Приём (SyncApply) — только через spaceAccept по закреплённому opub; раскол (две правки от одной эпохи) — флаг
// SpaceFork с M другой ветви, без запроса фразы: пропуска на этом ПК не выдаются, правки состава — отказ, пока
// слияние (окно, фраза) не даст M, продолжающий обе ветви.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"slices"
	"sync"
	"time"

	"anypc/agent"
)

const spaceLogMax = 16

var (
	errSpaceVia    = errors.New("пространство: пароль, код и «Спрашивать» этого ПК меняются через пространство (фраза)")
	errSpaceForked = errors.New("пространство: раскол состава — сначала слияние")
	errSpaceGap    = errors.New("пространство: в цепочке входа пропуск — нужна запись от другого члена")
	errSpaceSelf   = errors.New("пространство: этот ПК исключается с другого ПК пространства")
)

// spaceChanged — вход записи по умолчанию сменился правкой M: сессии со старым паролем рвать (agent.DropRevoked).
var spaceChanged func()

// spaceSetLocked — сделать проверенный n текущим составом (под c.mu, без save): смена входа — в цепочку и в запись
// по умолчанию (её Trusted/KeyLogin сбрасываются: пароль сменился; гостей не трогаем); раскол, который n продолжает,
// снят. drop — вход записи по умолчанию сменился.
func (c *config) spaceSetLocked(n *space) (drop bool, err error) {
	b, err := n.marshal()
	if err != nil {
		return false, err
	}
	if prev := c.spaceLocked(); prev != nil && prev.LGen != n.LGen {
		c.SpaceLog = append(c.SpaceLog, b)
		c.SpaceLog = c.SpaceLog[max(0, len(c.SpaceLog)-spaceLogMax):]
	}
	c.Space = b
	u := &c.Users[0]
	if drop = !bytes.Equal(u.Salt, n.PSalt) || !bytes.Equal(u.Hash, n.PHash) || u.TOTP != n.TOTP; drop {
		if u.TOTP != n.TOTP {
			u.TOTPStep = 0
		}
		u.Salt, u.Hash, u.TOTP, u.Trusted, u.KeyLogin = bytes.Clone(n.PSalt), bytes.Clone(n.PHash), n.TOTP, nil, nil
	}
	if f, err := spaceParse(c.SpaceFork); err != nil || spaceCovers(f, n) {
		c.SpaceFork = nil
	}
	return drop, nil
}

// spaceCovers — n продолжает ветвь f (или это она же).
func spaceCovers(f, n *space) bool {
	err := spaceAccept(f, n)
	return err == nil || errors.Is(err, errSpaceSame)
}

// spaceWalk — принять recs по порядку от from, как spaceAccept на каждом шаге: старые и те же — мимо; запись через
// смену входа, которой нет (r.LGen > x.LGen+1 и не продолжение x), — errSpaceGap, не раскол. Итог — принятые по порядку.
func spaceWalk(from *space, recs []*space) ([]*space, error) {
	x := from
	var ok []*space
	for _, r := range recs {
		if uint64(r.LGen) > uint64(x.LGen)+1 && !r.loginFrom(x) && r.Epoch > x.Epoch {
			return ok, errSpaceGap
		}
		switch err := spaceAccept(x, r); {
		case err == nil:
			x, ok = r, append(ok, r)
		case errors.Is(err, errSpaceStale), errors.Is(err, errSpaceSame):
		default:
			return ok, err
		}
	}
	return ok, nil
}

// spaceRecsLocked — записи цепочки, которых нет у p (вход и эпоха новее), по порядку, без текущего M (под c.mu).
func (c *config) spaceRecsLocked(p *space) []*space {
	cur := c.spaceLocked()
	var out []*space
	for _, b := range c.SpaceLog {
		if r, err := spaceParse(b); err == nil && cur != nil && r.sameSpace(p) && r.Epoch > p.Epoch && r.LGen > p.LGen && r.Epoch < cur.Epoch {
			out = append(out, r)
		}
	}
	return out
}

// SyncGate — agent.SpaceSyncer: M этого ПК ключу pub члена (или члена ветви peer того же пространства, если здесь
// он не исключён — ПК, вступивший через отставший P, иначе свой раскол не увидит).
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
	cur := c.spaceLocked()
	if cur == nil || bytes.Equal(pub, ed25519.PrivateKey(c.Key).Public().(ed25519.PublicKey)) || cur.gone(pub) ||
		!cur.member(pub) && (p == nil || !cur.sameSpace(p) || !p.member(pub)) {
		return nil
	}
	return bytes.Clone(c.Space)
}

// SyncRecs — agent.SpaceSyncer: записи цепочки для peer.
func (c *config) SyncRecs(peer []byte) [][]byte {
	p, err := spaceParse(peer)
	if err != nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	var out [][]byte
	for _, r := range c.spaceRecsLocked(p) {
		b, _ := r.marshal()
		out = append(out, b)
	}
	return out
}

// SyncApply — agent.SpaceSyncer: приём M другого члена (и записей перед ним); вернуть текущий M.
func (c *config) SyncApply(peer []byte, recs [][]byte) []byte {
	if err := c.spaceSync(peer, recs); err != nil && !errors.Is(err, errSpaceSame) {
		log.Printf("пространство: сверка: %v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.Space)
}

// spaceSync — p новее — принять записи и p по порядку; старее — проверить, что он предок текущего (иначе раскол);
// равная эпоха с другими байтами — раскол.
func (c *config) spaceSync(pb []byte, rb [][]byte) error {
	p, err := spaceParse(pb)
	if err != nil {
		return err
	}
	var recs []*space
	for _, b := range rb {
		r, err := spaceParse(b)
		if err != nil {
			return err
		}
		recs = append(recs, r)
	}
	c.mu.Lock()
	c.reload()
	cur, changed := c.spaceLocked(), false
	switch {
	case cur == nil:
		err = errSpaceNotIn
	case !cur.sameSpace(p):
		err = errSpaceForeign
	case p.Epoch > cur.Epoch:
		var ok []*space
		ok, err = spaceWalk(cur, append(recs, p))
		drop := false
		for _, x := range ok { // по шагу: каждая смена входа — в цепочку (отдавать следующему отставшему)
			d, serr := c.spaceSetLocked(x)
			if serr != nil {
				err = serr
				break
			}
			changed, drop = true, drop || d
		}
		if drop && spaceChanged != nil {
			defer spaceChanged() // после c.mu
		}
	case p.Epoch < cur.Epoch:
		_, err = spaceWalk(p, append(c.spaceRecsLocked(p), cur)) // так его примет отставший
	case !bytes.Equal(p.signBytes(), cur.signBytes()):
		err = errSpaceFork
	default:
		err = errSpaceSame
	}
	if errors.Is(err, errSpaceFork) {
		c.SpaceFork = bytes.Clone(pb)
		log.Printf("пространство: раскол состава (%v) — пропуска не выдаются до слияния", err)
	}
	if changed || errors.Is(err, errSpaceFork) {
		if serr := c.save(); serr != nil && err == nil {
			err = serr
		}
	}
	c.mu.Unlock()
	return err
}

// spaceResult — итог сверки с одним членом: State — "ok" (составы сошлись) | "differs" (раскол или неполная
// цепочка) | "offline" | "old" (версия без сверки) | "badid" (под ID ответил чужой ключ, С4) | "refused".
type spaceResult struct {
	ID    string
	State string
	Err   error
}

// spaceSyncer — рассылка состава этого ПК членам с повтором (как offRetry: пауза растёт до spaceSyncRetryMax).
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
)

func (s *spaceSyncer) bgCtx() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

// one — сверка с членом x; флаги С4 и «вступление не сверено» — по итогу.
func (s *spaceSyncer) one(ctx context.Context, x spaceMember) spaceResult {
	c := s.cfg
	same, err := spaceSyncFn(ctx, agent.SyncDial{Server: c.server(), ID: x.ID, HostPub: x.Pub, Key: c.key(), S: c})
	r := spaceResult{ID: x.ID, State: "refused", Err: err}
	switch {
	case err == nil && same:
		r.State = "ok"
	case err == nil:
		r.State = "differs"
	case errors.Is(err, agent.ErrSpaceOffline):
		r.State = "offline"
	case errors.Is(err, agent.ErrSpaceOld):
		r.State = "old"
	case errors.Is(err, agent.ErrSpaceIDKey):
		r.State = "badid"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	bad, ch := slices.Contains(c.SpaceBadID, x.ID), false
	switch {
	case r.State == "badid" && !bad:
		c.SpaceBadID, ch = append(c.SpaceBadID, x.ID), true
		log.Printf("пространство: под ID %s ответил не тот ПК — ему не доверяем", x.ID)
	case (r.State == "ok" || r.State == "differs") && bad: // ключ под этим ID доказан
		c.SpaceBadID, ch = slices.DeleteFunc(c.SpaceBadID, func(id string) bool { return id == x.ID }), true
	}
	if r.State == "ok" && c.SpaceWait != "" && c.SpaceWait != x.ID {
		c.SpaceWait, ch = "", true
	}
	if ch {
		c.save()
	}
	return r
}

// spread — сверка со всеми членами M, кроме себя, параллельно; retry — не дошедшее (не в сети, отказ) повторять в
// фоне до подтверждения, исключения цели или конца s.ctx.
func (s *spaceSyncer) spread(ctx context.Context, retry bool) []spaceResult {
	c := s.cfg
	c.mu.Lock()
	c.reload()
	m := c.spaceLocked()
	self := ed25519.PrivateKey(c.Key).Public().(ed25519.PublicKey)
	c.mu.Unlock()
	if m == nil {
		return nil
	}
	var targets []spaceMember
	for _, x := range m.Members {
		if !bytes.Equal(x.Pub, self) {
			targets = append(targets, x)
		}
	}
	out := make([]spaceResult, len(targets))
	var wg sync.WaitGroup
	for i, x := range targets {
		wg.Go(func() {
			out[i] = s.one(ctx, x)
			if retry && (out[i].State == "offline" || out[i].State == "refused") {
				s.later(x)
			}
		})
	}
	wg.Wait()
	return out
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
	s.bg.Go(func() {
		defer func() {
			s.mu.Lock()
			if s.retry[x.ID] == tok {
				delete(s.retry, x.ID)
			}
			s.mu.Unlock()
		}()
		for wait := spaceSyncRetry; ; wait = min(2*wait, spaceSyncRetryMax) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			s.mu.Lock()
			mine := s.retry[x.ID] == tok
			s.mu.Unlock()
			if c := s.cfg; !mine || c.SyncGate(x.Pub, nil) == nil { // заменён новой рассылкой или больше не член
				return
			}
			if r := s.one(ctx, x); r.State != "offline" && r.State != "refused" {
				return
			}
		}
	})
}

// spaceFresh — сразу после вступления (п. 5 Э4): сверка с остальными членами; P отдал старый состав (раскол с
// текущим) — слить этой же фразой (она ещё у вызывающего) и разослать. fresh — пропуска выдаются.
func (c *config) spaceFresh(ctx context.Context, phrase string) (fresh, merged bool) {
	if c.syn == nil {
		return c.spaceFreshNow(), false
	}
	c.syn.spread(ctx, true)
	c.mu.Lock()
	c.reload()
	m, raw := c.spaceLocked(), bytes.Clone(c.Space)
	f, _ := spaceParse(c.SpaceFork)
	c.mu.Unlock()
	if m != nil && f != nil {
		n, err := spaceMerge(m, f, phrase, "")
		if err != nil {
			log.Printf("пространство: состав ПК вступления старый, слить без окна нельзя: %v", err)
			return false, false
		}
		if _, err := c.spaceEdit(raw, n); err != nil {
			log.Printf("пространство: слияние не сохранено: %v", err)
			return false, false
		}
		c.syn.spread(ctx, true)
		merged = true
	}
	return c.spaceFreshNow(), merged
}

func (c *config) spaceFreshNow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.SpaceWait == "" && len(c.SpaceFork) == 0
}

// spaceEdit — сохранить правку n состава raw (если он не сменился за время правки).
func (c *config) spaceEdit(raw []byte, n *space) (bool, error) {
	c.mu.Lock()
	c.reload()
	if !bytes.Equal(c.Space, raw) {
		c.mu.Unlock()
		return false, errSpaceChange
	}
	drop, err := c.spaceSetLocked(n)
	if err == nil {
		err = c.save()
	}
	c.mu.Unlock()
	if err == nil && drop && spaceChanged != nil {
		spaceChanged()
	}
	return drop, err
}

// edit — правка состава фразой (f — правило ядра) с рассылкой: сперва сверка со всеми доступными (правка — от
// свежего M, а не от ветви, которую потом сливать), раскол — отказ.
func (s *spaceSyncer) edit(ctx context.Context, f func(m *space) (*space, error)) ([]spaceResult, error) {
	c := s.cfg
	s.spread(ctx, false)
	c.mu.Lock()
	c.reload()
	m, raw, fork := c.spaceLocked(), bytes.Clone(c.Space), len(c.SpaceFork) > 0
	c.mu.Unlock()
	switch {
	case m == nil:
		return nil, errSpaceNotIn
	case fork:
		return nil, errSpaceForked
	}
	n, err := f(m) // Argon2 фразы — без c.mu
	if err != nil {
		return nil, err
	}
	if _, err := c.spaceEdit(raw, n); err != nil {
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

// spaceChangeLogin — новый пароль входа пространства (запись по умолчанию на всех членах).
func (s *spaceSyncer) spaceChangeLogin(ctx context.Context, phrase, newPassword string) ([]spaceResult, error) {
	if len([]rune(newPassword)) < 8 {
		return nil, errors.New("пароль короче 8 символов")
	}
	return s.edit(ctx, func(m *space) (*space, error) { return spaceSetLogin(m, phrase, newPassword, "") })
}

// startSpaceSync — при запуске: рассылка правок с этого ПК, сверка со всеми членами (ПК мог пропустить правки, пока
// был выключен); вход сменился — рвать сессии со старым паролем.
func startSpaceSync(ctx context.Context, cfg *config, a *agent.Agent) {
	cfg.syn = &spaceSyncer{cfg: cfg, ctx: ctx}
	spaceChanged = a.DropRevoked
	cfg.syn.bg.Go(func() { cfg.syn.spread(ctx, true) })
}
