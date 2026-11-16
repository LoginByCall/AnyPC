package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"log"
	"slices"
	"sync/atomic"
	"time"

	"anypc/hub"
	"anypc/pake"
)

// Ч10.1 «приём на хосте» (agent/recv.go): закреплённые ключи чужих отправителей. Чужой ПК, приславший сюда файлы
// разовым кодом, закрепляется (решение владельца A); дальше он шлёт без кода — окно «Принять?». ТРЕБУЕТ РЕВЬЮ
// ЧЕЛОВЕКОМ (A13): закрепление ключа.

// recvPin — закреплённый отправитель: ID и имя — заявленные им (подсказка в окне), ключ — доказанный подписью.
type recvPin struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Pub  []byte `json:"pub"`
	At   int64  `json:"at,omitempty"` // unix: когда закреплён (лишние — самые давние)
}

// maxRecvPins — закреплённых отправителей; лишние — самые давние.
const maxRecvPins = 32

// valid — запись годна (файл могли править руками): ключ 32 байта, ID — 9 цифр или пусто, имя — как имя записи.
func (p recvPin) valid() bool {
	return len(p.Pub) == ed25519.PublicKeySize && (p.ID == "" || hub.IsHostID(p.ID)) && (p.Name == "" || validName(p.Name))
}

// recvPinned — agent.Agent.RecvPinned: ключ закреплён (негодные записи не действуют); id и name — закреплённые,
// только они идут в окно «Принять?» (B2 приёмки).
func (c *config) recvPinned(pub []byte) (id, name string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload() // закрепление могли снять из другого процесса (окно, CLI)
	for _, p := range c.RecvPins {
		if p.valid() && bytes.Equal(p.Pub, pub) {
			return p.ID, p.Name, true
		}
	}
	return "", "", false
}

// recvPinNew — последнее новое закрепление: для уведомления в окне (Ч10.5); nil — не было.
var recvPinNew atomic.Pointer[recvPin]

// recvPin — agent.Agent.RecvPin: закрепить ключ после приёма разовым кодом (уже закреплённый — обновить ID, имя).
// Заявленные ID и имя, не прошедшие проверку, не сохраняются.
func (c *config) recvPin(pub []byte, id, name string) {
	if len(pub) != ed25519.PublicKeySize {
		return
	}
	if !hub.IsHostID(id) {
		id = ""
	}
	if !validName(name) {
		name = ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	known := slices.ContainsFunc(c.RecvPins, func(p recvPin) bool { return p.valid() && bytes.Equal(p.Pub, pub) })
	l := slices.DeleteFunc(c.RecvPins, func(p recvPin) bool { return !p.valid() || bytes.Equal(p.Pub, pub) })
	pin := recvPin{ID: id, Name: name, Pub: bytes.Clone(pub), At: time.Now().Unix()}
	l = append(l, pin)
	if !known { // новое закрепление — в журнал и окну (M8 приёмки)
		log.Printf("закреплён отправитель %q (ID %s, ключ %s): дальше — «Принять?» без кода", name, id, pake.KeyFingerprint(pub)[:9])
		recvPinNew.Store(&pin)
	}
	if n := len(l) - maxRecvPins; n > 0 {
		l = l[n:]
	}
	c.RecvPins = l
	if err := c.save(); err != nil {
		log.Printf("закрепление отправителя: %v", err)
	}
}

// recvUnpin — отозвать закреплённый ключ (окно — Ч10.5): дальше этот ПК снова шлёт только с разовым кодом.
func (c *config) recvUnpin(pub []byte) (bool, error) {
	c.mu.Lock()
	c.reload()
	n := len(c.RecvPins)
	c.RecvPins = slices.DeleteFunc(c.RecvPins, func(p recvPin) bool { return bytes.Equal(p.Pub, pub) })
	if len(c.RecvPins) == n {
		c.mu.Unlock()
		return false, nil
	}
	err := c.save()
	c.mu.Unlock()
	log.Printf("отправитель откреплён: ключ %s", pake.KeyFingerprint(pub)[:9])
	if drop := spaceChanged; drop != nil { // DropRevoked (читает настройки — без c.mu): сессии приёма этого ключа рвутся (B3)
		drop()
	}
	return true, err
}

var errPinNone = errors.New("отправка: такого закреплённого отправителя нет")

// recvUnpinFP — «Отозвать» окна: по отпечатку ключа (странице ключ целиком не нужен).
func (c *config) recvUnpinFP(fp string) error {
	for _, p := range c.recvPinList() {
		if fp != "" && pake.KeyFingerprint(p.Pub) == fp {
			_, err := c.recvUnpin(p.Pub)
			return err
		}
	}
	return errPinNone
}

// recvPinsInfo — окну («Доступ к этому ПК»): закреплённые отправители (id, name — заявленные ими при закреплении,
// fp — отпечаток доказанного ключа, at — когда) и последнее новое закрепление (new; null — нет или прочитано).
func recvPinsInfo(c *config) map[string]any {
	l := []map[string]any{}
	for _, p := range c.recvPinList() {
		l = append(l, recvPinJSON(p))
	}
	var nw any
	if p := recvPinNew.Load(); p != nil {
		nw = recvPinJSON(*p)
	}
	return map[string]any{"pins": l, "new": nw}
}

func recvPinJSON(p recvPin) map[string]any {
	return map[string]any{"id": p.ID, "name": p.Name, "fp": pake.KeyFingerprint(p.Pub), "at": p.At}
}

// recvPinList — закреплённые отправители (для окна, Ч10.5): только годные, копия.
func (c *config) recvPinList() []recvPin {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []recvPin
	for _, p := range c.RecvPins {
		if p.valid() {
			p.Pub = bytes.Clone(p.Pub)
			out = append(out, p)
		}
	}
	return out
}

// recvPinNewJSON — hostInfo.recvNew: новое закрепление, пока оно в силе и не прочитано (recvPinSeen); иначе nil.
func recvPinNewJSON(c *config) any {
	p := recvPinNew.Load()
	if p == nil {
		return nil
	}
	if _, _, ok := c.recvPinned(p.Pub); !ok { // уже отозвано — не о чем уведомлять
		return nil
	}
	return recvPinJSON(*p)
}
