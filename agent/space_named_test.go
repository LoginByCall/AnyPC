package agent

// Named-вступление в пространство (учётные записи, REQ-S-20): инициатор с полными постоянными реквизитами (запись
// по имени, пароль и код TOTP) вступает без фразы пространства и без окна «Пустить?». Хост сам решает eligibility
// (app в SpaceJoin по соли записи) и сам подписывает новый M — клиент ключа владельца не получает и возвращает
// состав из OK хоста, а не то, что отправлял сам.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// spRaw — spMsg для spaceCtl.
func spRaw(t *testing.T, m spMsg) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSpaceCtlNamed — named-сессия в ctl "sp": состав отдаётся сразу, без окна «Пустить?» и без "rights"; заявка
// уходит в SpaceJoin с заявленным в "b" ID (claimID) и доказанным ключом; OK несёт актуальный состав хоста.
func TestSpaceCtlNamed(t *testing.T) {
	r := newSpaceRig(newAgent("ws://localhost:1", "123456789", nil)) // хаб не нужен: spaceCtl зовётся напрямую
	_, nkey, _ := ed25519.GenerateKey(nil)
	cpub := nkey.Public().(ed25519.PublicKey)
	windows := 0
	r.a.SpaceAdmit = func(context.Context, AdmitReq) AdmitResult {
		windows++
		return AdmitNo
	}
	get := r.a.SpaceGet
	r.a.SpaceGetTagged = func(salt, tag []byte) [][]byte { return get(salt) }
	r.a.SpaceJoinTagged = func(salt, tag, m []byte, pub ed25519.PublicKey, id string) error {
		return r.a.SpaceJoin(salt, m, pub, id)
	}
	r.a.SpaceGet = func([]byte) [][]byte {
		t.Fatal("named-ответ использует непомеченный SpaceGet")
		return nil
	}
	r.a.SpaceJoin = func(js, jm []byte, pub ed25519.PublicKey, id string) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !bytes.Equal(js, namedSalt) || id == "" {
			return errors.New("тест: не принят")
		}
		r.joined, r.joinPub, r.joinID = bytes.Clone(jm), pub, id
		r.m = append(bytes.Clone(jm), "+P"...) // хост «сам подписал» новый состав
		return nil
	}
	s := &session{cid: "ctl-named", user: "alice"}
	s.spaceOK.Store(true)
	s.mu.Lock()
	s.salt, s.cpub, s.claimID, s.claimName = bytes.Clone(namedSalt), bytes.Clone(cpub), "987654321", "Ноутбук"
	s.mu.Unlock()
	r.mu.Lock()
	m0 := bytes.Clone(r.m)
	r.mu.Unlock()
	var out []spMsg
	reply := func(m spMsg) { out = append(out, m) }
	// запрос состава: ответ сразу — окно не открывается, "rights" нет
	r.a.spaceCtl(context.Background(), s, spRaw(t, spMsg{T: "sp"}), reply)
	if len(out) != 1 || !bytes.Equal(out[0].M, m0) || out[0].Err != "" {
		t.Fatalf("запрос состава: %+v (окон %d)", out, windows)
	}
	// заявка M: SpaceJoin получает claimID и доказанный ключ, OK — новый состав хоста
	r.mu.Lock()
	r.heads = [][]byte{[]byte("H-1")}
	r.mu.Unlock()
	claim := []byte("M-ALICE-CLAIM")
	r.a.spaceCtl(context.Background(), s, spRaw(t, spMsg{T: "sp", M: claim}), reply)
	r.mu.Lock()
	joined, jp, jid, m := r.joined, r.joinPub, r.joinID, r.m
	r.mu.Unlock()
	if windows != 0 {
		t.Errorf("окно «Пустить?» открыто %d раз", windows)
	}
	if !bytes.Equal(joined, claim) || !bytes.Equal(jp, cpub) || jid != "987654321" {
		t.Errorf("SpaceJoin: состав %q, ключ %v, ID %q", joined, jp, jid)
	}
	if len(out) != 2 || !out[1].OK || !bytes.Equal(out[1].M, m) || len(out[1].H) != 1 || !bytes.Equal(out[1].H[0], []byte("H-1")) {
		t.Errorf("ответ на заявку: %+v (состав хоста %q)", out[1], m)
	}
}

func TestSpaceCtlNamedTOTPChanged(t *testing.T) {
	r := newSpaceRig(newAgent("ws://localhost:1", "123456789", nil))
	secret := "totp-v1"
	r.a.LoginTag = func(string, []byte) []byte { return []byte(secret) }
	s := &session{cid: "ctl-named-stale", user: "alice", tag: []byte("totp-v1"), tagged: true}
	s.spaceOK.Store(true)
	s.salt = bytes.Clone(namedSalt)
	secret = "totp-v2"
	var out []spMsg
	r.a.spaceCtl(context.Background(), s, spRaw(t, spMsg{T: "sp"}), func(m spMsg) { out = append(out, m) })
	if len(out) != 1 || out[0].Err != "rights" {
		t.Fatalf("сессия со старым TOTP сохранила доступ: %+v", out)
	}
}

// TestSpaceJoinNamed — named-вступление по сети: вход в запись по имени (named CPace: первое "a" → имя → второе
// "a" → "b"), код записи, без фразы и без окна «Пустить?»; Sign возвращает M как был — заявка уходит хосту, хост
// подписывает новый состав и клиент возвращает именно его.
func TestSpaceJoinNamed(t *testing.T) {
	url := local(t)
	r := spaceHost(t, url, "123456789", func(r *spaceRig) {
		get := r.a.SpaceGet
		r.a.SpaceGetTagged = func(salt, tag []byte) [][]byte { return get(salt) }
		r.a.SpaceJoinTagged = func(salt, tag, m []byte, pub ed25519.PublicKey, id string) error {
			return r.a.SpaceJoin(salt, m, pub, id)
		}
		r.a.SpaceGet = func([]byte) [][]byte {
			t.Fatal("named-ответ использует непомеченный SpaceGet")
			return nil
		}
		r.a.SpaceJoin = func(js, jm []byte, pub ed25519.PublicKey, id string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			if !bytes.Equal(js, namedSalt) || id == "" {
				return errors.New("тест: не принят")
			}
			r.joined, r.joinPub, r.joinID = bytes.Clone(jm), pub, id
			r.m = append(bytes.Clone(jm), "+P"...) // хост сам подписал новый состав
			return nil
		}
	})
	_, nkey, _ := ed25519.GenerateKey(nil)
	var signed []byte
	var stages []string
	out, err := SpaceJoin(context.Background(), SpaceDial{Server: url, ID: "123456789", Key: nkey,
		Password: "alice-pass1", Code: r.named.code(), User: " Alice ", Self: "987654321", Name: "Ноутбук",
		Stage: func(s string) { stages = append(stages, s) },
		Sign: func(m []byte, _ ed25519.PublicKey, _ ...[]byte) ([]byte, error) {
			signed = bytes.Clone(m)
			return bytes.Clone(m), nil // named: ключа владельца нет — M без изменений и есть заявка
		}})
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	joined, jp, jid, m := r.joined, r.joinPub, r.joinID, r.m
	r.mu.Unlock()
	if !bytes.Equal(out, m) || !bytes.HasSuffix(out, []byte("+P")) {
		t.Errorf("клиент получил %q, состав хоста %q", out, m)
	}
	if !bytes.Equal(joined, signed) || !bytes.Equal(signed, []byte("M-SECRET-MARK-1")) {
		t.Errorf("заявка %q, хост принял %q", signed, joined)
	}
	if !bytes.Equal(jp, nkey.Public().(ed25519.PublicKey)) || jid != "987654321" {
		t.Errorf("ключ нового ПК %v, ID %q", jp, jid)
	}
	if strings.Join(stages, ",") != "link,auth,list" {
		t.Errorf("стадии %v (окна «Пустить?» быть не должно)", stages)
	}
}
