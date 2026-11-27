package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"anypc/agent"
	"anypc/totp"
)

func initiatorHost(t *testing.T) (*config, []byte) {
	t.Helper()
	dir := t.TempDir()
	old := spaceDownloadsDir
	spaceDownloadsDir = func() string { return dir }
	t.Cleanup(func() { spaceDownloadsDir = old })
	c := spaceCfg(t, spacePass, totp.NewSecret())
	if _, err := c.spaceCreateFile(); err != nil {
		t.Fatal(err)
	}
	sec := totp.NewSecret()
	code, _ := totp.Code(sec, time.Now())
	if err := c.saveUser("initiator", "initiator-pass", "full", sec, code); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	salt := bytes.Clone(c.user("initiator").Salt)
	c.mu.Unlock()
	return c, salt
}

func TestSpaceJoinInitiatorHostSigns(t *testing.T) {
	c, salt := initiatorHost(t)
	before := bytes.Clone(c.Space)
	pub := spacePub(0x91)
	if err := c.spaceJoinSaveTagged(salt, c.loginTag("initiator", nil), before, pub, "100000091"); err != nil {
		t.Fatal(err)
	}
	m := spaceOf(c)
	if m == nil || !m.has(spaceMember{ID: "100000091", Pub: pub}) {
		t.Fatal("Инициатор не добавлен в подписанный хостом состав")
	}
	if got := c.spaceGetTagged(salt, c.loginTag("initiator", nil)); len(got) == 0 || !bytes.Equal(got[0], c.Space) {
		t.Fatal("Инициатор не получает актуальный состав")
	}

	c.mu.Lock()
	c.user("initiator").View = true
	c.save()
	c.mu.Unlock()
	if err := c.spaceJoinSaveTagged(salt, c.loginTag("initiator", nil), c.Space, spacePub(0x92), "100000092"); err == nil {
		t.Fatal("запись «только просмотр» добавила ПК в пространство")
	}
}

func TestSpacePhraseMigrationAndSelection(t *testing.T) {
	dir := t.TempDir()
	old := spaceDownloadsDir
	spaceDownloadsDir = func() string { return dir }
	t.Cleanup(func() { spaceDownloadsDir = old })
	c := spaceCfg(t, spacePass, totp.NewSecret())
	phrase := spaceMake(t, c) // пространство прежней версии: локального файла нет
	if _, err := c.spacePhrase(); !errors.Is(err, errSpacePhraseFile) {
		t.Fatalf("отсутствие файла: %v", err)
	}
	if _, err := c.spacePhraseFor(phrase); err != nil {
		t.Fatal(err)
	}
	if got, err := c.spacePhrase(); err != nil || got != phrase {
		t.Fatalf("миграция фразы: %q %v", got, err)
	}
	if err := c.spaceLeave("", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.spaceCreateFile(); err != nil {
		t.Fatal(err)
	}
	got, err := c.spacePhrase()
	if err != nil || got == phrase {
		t.Fatalf("после пересоздания выбрана старая фраза: %q %v", got, err)
	}
	sec := totp.NewSecret()
	code, _ := totp.Code(sec, time.Now())
	if err := c.saveUser("initiator", "initiator-pass", "full", sec, code); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	salt := bytes.Clone(c.user("initiator").Salt)
	c.mu.Unlock()
	pub := spacePub(0x92)
	if err := c.spaceJoinSaveTagged(salt, c.loginTag("initiator", nil), c.Space, pub, "100000092"); err != nil {
		t.Fatal(err)
	}
	if !spaceOf(c).has(spaceMember{ID: "100000092", Pub: pub}) {
		t.Fatal("после пересоздания Инициатор не добавлен")
	}
}

func TestNamedLoginTagTOTP(t *testing.T) {
	c, salt := initiatorHost(t)
	before := c.loginTag("initiator", nil)
	sec := totp.NewSecret()
	code, _ := totp.Code(sec, time.Now())
	if err := c.otpEnable(sec, code, "initiator"); err != nil {
		t.Fatal(err)
	}
	after := c.loginTag("initiator", nil)
	if len(before) == 0 || len(after) == 0 || bytes.Equal(before, after) {
		t.Fatal("смена TOTP не изменила метку именной записи")
	}
	if err := c.spaceJoinSaveTagged(salt, before, c.Space, spacePub(0x93), "100000093"); !errors.Is(err, agent.ErrSpaceAuth) {
		t.Fatalf("старый TOTP принят после смены: %v", err)
	}
}

func TestSpaceEnterInitiatorAccount(t *testing.T) {
	host, salt := initiatorHost(t)
	n := spaceCfg(t, "local-pass", totp.NewSecret())
	withSpaceNet(t, func(_ context.Context, d agent.SpaceDial) ([]byte, error) {
		if d.User != "initiator" || d.Password != "initiator-pass" || d.Code != "123456" {
			t.Fatalf("данные Инициатора: user=%q password=%q code=%q", d.User, d.Password, d.Code)
		}
		out, err := d.Sign(host.Space, cfgPub(host))
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(out, host.Space) {
			t.Fatal("Инициатор подписал состав сам вместо запроса подписи хоста")
		}
		pub := d.Key.Public().(ed25519.PublicKey)
		if err := host.spaceJoinSaveTagged(salt, host.loginTag("initiator", nil), out, pub, d.Self); err != nil {
			return nil, err
		}
		if d.Heads != nil {
			phrase, err := host.spacePhrase()
			if err != nil {
				return nil, err
			}
			parallel, err := spaceSetLogin(spaceOf(host), phrase, "parallel-pass", "")
			if err != nil {
				return nil, err
			}
			raw, err := parallel.marshal()
			if err != nil {
				return nil, err
			}
			*d.Heads = [][]byte{bytes.Clone(host.Space), raw}
		}
		return bytes.Clone(host.Space), nil // agent возвращает новый M, подписанный хостом
	})
	if _, err := n.spaceEnterAccount(context.Background(), host.id(), "initiator", "initiator-pass", "123456"); err != nil {
		t.Fatal(err)
	}
	m := spaceOf(n)
	if m == nil || !m.has(spaceMember{ID: n.id(), Pub: cfgPub(n)}) {
		t.Fatal("Инициатор не сохранил подписанный хостом состав")
	}
	if len(n.SpaceHeads) != 1 {
		t.Fatalf("потеряны параллельные верхушки: %d", len(n.SpaceHeads))
	}
}
