package main

// Ч10.4 «Избранные» (UI-REDESIGN.md, «Ч10 «Отправить»»): чужие ПК, которым этот ПК отправляет. Запись — только ID и
// имя (своё, для окна и трея); ключ того ПК — прежний known (TOFU после первой отправки по коду или входа), он общий с
// подключением для управления и здесь не меняется. Свои ПК (состав M) — не избранные: они в «Моём пространстве».
//
// Направления (не путать): отправка по коду закрепляет ключ ЭТОГО ПК на ТОМ (его recv_pins) — снять это может только
// владелец того ПК («Доступ к этому ПК» там). «Убрать» здесь стирает запись избранного; с unpin — ещё и закрепление
// ТОГО ПК как отправителя СЮДА (recv_pins этого ПК, recvUnpin), если он когда-то присылал сюда кодом: совпадение — по
// доказанному ключу (known того ID = отпечаток закреплённого ключа), а не по заявленному ID.
// ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (A13): сопоставление ключей при отзыве.

import (
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"anypc/hub"
	"anypc/pake"
)

// sendFav — избранный ПК: ID и имя ("" — показывать ID).
type sendFav struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

const (
	maxSendFavs = 64 // избранных; больше — отказ send:favmax (не вытеснять молча)
	favNameMax  = 40 // знаков в имени — как NAME_MAX «Моих ПК» окна
)

var (
	errFavName = errors.New("отправка: негодное имя избранного")
	errFavMax  = errors.New("отправка: избранных слишком много")
	errFavOwn  = errors.New("отправка: это ваш ПК — он в «Моём пространстве»")
	errFavNone = errors.New("отправка: такого избранного нет")
)

// favName — имя после обрезки пробелов: до favNameMax знаков, UTF-8, без управляющих, Cf (подмена направления, ZW*)
// и разделителей строк; "" — годно (без имени).
func favName(n string) (string, bool) {
	n = strings.TrimSpace(n)
	if !utf8.ValidString(n) || utf8.RuneCountInString(n) > favNameMax {
		return "", false
	}
	for _, r := range n {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return "", false
		}
	}
	return n, true
}

// favMemberLocked — id в составе M этого ПК (под c.mu).
func (c *config) favMemberLocked(id string) bool {
	if m := c.spaceLocked(); m != nil {
		return slices.ContainsFunc(m.Members, func(x spaceMember) bool { return x.ID == id })
	}
	return false
}

// favSet — добавить избранное или переименовать (add=false — только переименовать существующее).
func (c *config) favSet(id, name string, add bool) error {
	n, ok := favName(name)
	switch {
	case !hub.IsHostID(id):
		return errSendID
	case !ok:
		return errFavName
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	switch {
	case id == c.ID:
		return errSendSelf
	case c.favMemberLocked(id):
		return errFavOwn
	}
	if i := slices.IndexFunc(c.Favs, func(f sendFav) bool { return f.ID == id }); i >= 0 {
		c.Favs[i].Name = n
		return c.save()
	}
	if !add {
		return errFavNone
	}
	if len(c.Favs) >= maxSendFavs {
		return errFavMax
	}
	c.Favs = append(c.Favs, sendFav{ID: id, Name: n})
	return c.save()
}

// favDel — убрать из избранных; unpin — и отозвать закрепление того ПК как отправителя сюда (см. начало файла).
// unpinned — закрепление было и снято.
func (c *config) favDel(id string, unpin bool) (unpinned bool, err error) {
	c.mu.Lock()
	c.reload()
	i := slices.IndexFunc(c.Favs, func(f sendFav) bool { return f.ID == id })
	if i < 0 {
		c.mu.Unlock()
		return false, errFavNone
	}
	c.Favs = slices.Delete(c.Favs, i, i+1)
	err = c.save()
	pub := c.favPinLocked(id)
	c.mu.Unlock()
	if err != nil || !unpin || pub == nil {
		return false, err
	}
	return c.recvUnpin(pub)
}

// favPinLocked — закреплённый здесь ключ отправителя, совпадающий с known[id] (доказанный ключ того ПК); nil — нет.
func (c *config) favPinLocked(id string) []byte {
	fp := c.Known[id]
	if fp == "" {
		return nil
	}
	for _, p := range c.RecvPins {
		if p.valid() && pake.KeyFingerprint(p.Pub) == fp {
			return p.Pub
		}
	}
	return nil
}

// favList — избранные для окна и трея: id, name, fp (known; "" — первый раз нужен код), pinned (тот ПК может
// присылать сюда без кода). Записи из файла с негодным ID или именем, свои ПК и этот ПК — не показываются.
func (c *config) favList() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	out := []map[string]any{}
	for _, f := range c.Favs {
		n, ok := favName(f.Name)
		if !ok || !hub.IsHostID(f.ID) || f.ID == c.ID || c.favMemberLocked(f.ID) {
			continue
		}
		out = append(out, map[string]any{"id": f.ID, "name": n, "fp": c.Known[f.ID], "pinned": c.favPinLocked(f.ID) != nil})
	}
	return out
}
