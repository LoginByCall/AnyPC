package main

// Э5: настройки выпущенных версий. testdata/config-v0.1.27.json и config-v0.2.0.json записаны кодом этих тегов
// (git archive, тот же config.go): пароль и TOTP записи по умолчанию, ключ У3, вход ключом, гость ivan с TOTP и У3,
// «Известные», сохранённый пароль, ключ клиента (ckeys), «Только показ экрана», у v0.2.0 — окно (ui).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"anypc/agent"
	"anypc/pake"
	"anypc/totp"
)

const relSec, relGuestSec = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU" // секреты фикстур

// relServer — хаб вместо боевого из фикстуры: порт 1 закрыт, тест в сеть не выходит (замечание M1 приёмки Э5).
const relServer = "ws://127.0.0.1:1/ws"

// relConfig — фикстура версии v с добавками extra (ключ JSON → значение) в новом файле; server — relServer.
func relConfig(t *testing.T, v string, extra map[string]json.RawMessage) (path string, orig map[string]any) {
	t.Helper()
	b, err := os.ReadFile("testdata/config-" + v + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(b, &raw)
	json.Unmarshal(b, &orig)
	raw["server"], orig["server"] = json.RawMessage(`"`+relServer+`"`), relServer
	maps.Copy(raw, extra)
	b, _ = json.Marshal(raw)
	path = filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, b, 0o600)
	return path, orig
}

// relCheck — в c всё, что задала фикстура; otp — проверить и коды (код принимается один раз на шаг).
func relCheck(t *testing.T, c *config, ui, otp bool) {
	t.Helper()
	if s, h, view := c.secret(""); view || !bytes.Equal(h, pake.KDF("пароль-владельца", s)) {
		t.Error("пароль записи по умолчанию")
	}
	if s, h, view := c.secret("ivan"); !view || !bytes.Equal(h, pake.KDF("пароль-ивана", s)) {
		t.Error("пароль или права записи ivan")
	}
	if c.Users[0].TOTP != relSec || c.user("ivan").TOTP != relGuestSec {
		t.Error("секреты TOTP")
	}
	if otp {
		now := time.Now()
		code, _ := totp.Code(relSec, now)
		gcode, _ := totp.Code(relGuestSec, now)
		if set, ok := c.otp("", code); !set || !ok {
			t.Error("TOTP записи по умолчанию")
		}
		if set, ok := c.otp("ivan", gcode); !set || !ok {
			t.Error("TOTP записи ivan")
		}
	}
	k1, k2, k3 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	if !c.trusted(k1, "") || c.trusted(k1, "ivan") || !c.trusted(k3, "ivan") {
		t.Error("ключи У3")
	}
	if in, on := c.keyLogin(k2, ""); !in || !on {
		t.Errorf("вход ключом: в списке %v, действует %v", in, on)
	}
	if c.confirm() || !c.viewOnly() || c.knownGet("987654321") != "AA:BB" || c.savedGet("987654321") != "сохранённый" ||
		!strings.Contains(c.ckeyGet("987654321"), `"lu":"ivan"`) {
		t.Error("режим, «Известные», сохранённый пароль или ключ клиента")
	}
	if c.UIPort == 0 || c.server() != relServer {
		t.Errorf("порт окна %d, хаб %q", c.UIPort, c.server())
	}
	if g := c.uiGet(); ui && (g["mine"] != `[{"id":"987654321","name":"Дача"}]` || g["recent"] != `["987654321"]` || g["turn"] != `"auto"` ||
		g["tour_home"] != "1" || g["tour_sess"] != "1" || g["turbo"] != "1" || g["stats"] != "true" || g["users"] != `{"987654321":"ivan"}`) {
		t.Errorf("окно: %v", g)
	}
}

// TestConfigReleases — config.json v0.1.27 и v0.2.0 читается без потерь и после записи текущим кодом остаётся тем же
// (кроме правленного ключа); ключи прежней схемы пространства (space_log, space_fork, space_bad_id, space_behind —
// невыпущенные сборки Э4) не мешают и при записи уходят.
func TestConfigReleases(t *testing.T) {
	old := map[string]json.RawMessage{"space_log": json.RawMessage(`["AAEC"]`), "space_fork": json.RawMessage(`"2026-11-14 раскол"`),
		"space_bad_id": json.RawMessage(`["123456789"]`), "space_behind": json.RawMessage(`true`)}
	for _, v := range []string{"v0.1.27", "v0.2.0"} {
		t.Run(v, func(t *testing.T) {
			p, orig := relConfig(t, v, old)
			c, err := loadConfig(p)
			if err != nil {
				t.Fatal(err)
			}
			relCheck(t, c, v == "v0.2.0", true)
			if port, _ := orig["ui_port"].(float64); port == 0 || c.UIPort != int(port) { // M2: тег ui_port
				t.Errorf("порт окна %d, в файле %v", c.UIPort, orig["ui_port"])
			}
			if len(c.Space) != 0 || c.spaceDamaged() || c.loginTag("", nil) == nil {
				t.Error("пространство из ниоткуда")
			}
			if err := c.savedSet("111222333", "другой"); err != nil { // любая правка — файл переписан текущим кодом
				t.Fatal(err)
			}
			var got map[string]any
			b, _ := os.ReadFile(p)
			json.Unmarshal(b, &got)
			for _, k := range slices.Collect(maps.Keys(old)) {
				if _, ok := got[k]; ok {
					t.Errorf("ключ прежней схемы %s остался", k)
				}
			}
			delete(got, "saved")
			delete(orig, "saved")
			for _, u := range []map[string]any{got, orig} { // шаг TOTP сдвинулся проверкой кода выше
				for _, x := range u["users"].([]any) {
					delete(x.(map[string]any), "totp_step")
				}
			}
			if got["allow_space"] != true {
				t.Errorf("прежний permanent-профиль не мигрирован: %v", got["allow_space"])
			}
			delete(got, "allow_space") // поле добавлено новой схемой после исходного выпуска
			if !reflect.DeepEqual(got, orig) {
				t.Errorf("файл после записи:\n%s", b)
			}
			c2, err := loadConfig(p)
			if err != nil {
				t.Fatal(err)
			}
			relCheck(t, c2, v == "v0.2.0", false)
		})
	}
}

// TestSpaceCreateKeeps — создание пространства на ПК с настройками v0.2.0 (У3, вход ключом, гость, TOTP): всё
// остаётся, метка входа записи по умолчанию та же (сессии не рвутся), в M — её соль, хэш и секрет TOTP.
// Вступление (меняет запись по умолчанию, сбрасывает её У3 и ключи) — TestSpaceEnterSideEffects.
func TestSpaceCreateKeeps(t *testing.T) {
	p, _ := relConfig(t, "v0.2.0", nil)
	c, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	tag := c.loginTag("", nil)
	if _, err := c.spaceCreate("пароль-владельца"); err != nil {
		t.Fatal(err)
	}
	relCheck(t, c, true, true)
	c.mu.Lock()
	m, u := c.spaceLocked(), c.Users[0]
	c.mu.Unlock()
	if m == nil || !bytes.Equal(m.PSalt, u.Salt) || !bytes.Equal(m.PHash, u.Hash) || m.TOTP != relSec || !bytes.Equal(c.loginTag("", nil), tag) {
		t.Error("вход в M — не запись по умолчанию, или метка входа сменилась")
	}
}

// TestConfigSpaceV1 — в "space" запись M v1 (формат v0.2.0, spaceVer=1: руками или ошибкой). Явное поведение:
// состав не читается (errSpaceVersion) — «испорчено» (окно: spaceDamaged); запуск без ошибки, запись M не стирается;
// запись по умолчанию входит как прежде (пароль, TOTP, У3, ключ); смена пароля — errSpaceVia, создание и вступление —
// errSpaceDamaged; выход (пароль + код) убирает запись M и оставляет запись по умолчанию как была.
func TestConfigSpaceV1(t *testing.T) {
	b, _ := os.ReadFile("testdata/config-v0.2.0.json")
	var s settings
	json.Unmarshal(b, &s)
	u := s.Users[0]
	m, phrase, err := spaceNew(u.Salt, u.Hash, u.TOTP, s.ID, ed25519.PrivateKey(s.Key).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	mb, _ := m.marshal()
	mb[len(spaceDomain)] = 1 // байт версии; разбор v1 кончается на нём (поля v1 дальше — другие)
	if _, err := spaceParse(mb); !errors.Is(err, errSpaceVersion) {
		t.Fatalf("M v1: %v", err)
	}
	sp, _ := json.Marshal(mb)
	p, _ := relConfig(t, "v0.2.0", map[string]json.RawMessage{"space": sp})
	withSpaceNet(t, func(_ context.Context, d agent.SpaceDial) ([]byte, error) { // M1: сломанная защита — не в сеть
		t.Errorf("вступление при испорченной записи дошло до сети (%s)", d.Server)
		return nil, agent.ErrSpaceOffline
	})
	c, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if !c.spaceDamaged() || !bytes.Equal(c.Space, mb) {
		t.Fatal("M v1 — не «испорчено» или стёрта")
	}
	relCheck(t, c, true, true)
	if tag := c.loginTag("", nil); tag == nil || !bytes.Equal(tag, c.loginTag("", nil)) {
		t.Error("метка входа: нет или меняется (сессии рвались бы циклом)")
	}
	if err := c.setPassword("новый-пароль-1"); !errors.Is(err, errSpaceVia) {
		t.Errorf("смена пароля: %v", err)
	}
	if _, err := c.spaceCreate("пароль-владельца"); !errors.Is(err, errSpaceDamaged) {
		t.Errorf("создание: %v", err)
	}
	if _, err := c.spaceEnter(context.Background(), "987654321", "пароль-владельца", "000000", phrase); !errors.Is(err, errSpaceDamaged) {
		t.Errorf("вступление: %v", err)
	}
	if c2, _ := loadConfig(p); !bytes.Equal(c2.Space, mb) {
		t.Error("M v1 стёрта записью")
	}
	before := c.Users[0]
	code, _ := totp.Code(relSec, time.Now().Add(totp.Period*time.Second)) // код этого шага уже вошёл (relCheck)
	if err := c.spaceLeave("пароль-владельца", code); err != nil {
		t.Fatal(err)
	}
	after := c.Users[0]
	before.TOTPStep, after.TOTPStep = 0, 0
	if c.spaceDamaged() || len(c.Space) != 0 || !reflect.DeepEqual(before, after) {
		t.Error("выход: M осталась или запись по умолчанию изменилась")
	}
	if err := c.setPassword("новый-пароль-1"); err != nil {
		t.Errorf("смена пароля после выхода: %v", err)
	}
}
