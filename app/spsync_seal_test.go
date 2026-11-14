package main

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"anypc/hub"
	"anypc/totp"
)

// TestSpaceSyncKeys — Э4в + 2P-Set: SyncKeys (ими цель открывает sx connect) — ровно те ключи, для которых SyncKey —
// true, на объединении двух верхушек (в одной исключён keys[0], в другой — он член и добавлен x): члены объединения,
// кроме своего и исключённого хоть в одной верхушке, без повторов.
func TestSpaceSyncKeys(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 2, ca, cb) // keys[0] исключим, keys[1] — член
	m := spaceOf(ca)
	cur, err := spaceRemove(m, ph, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	x, _, _ := ed25519.GenerateKey(nil) // только во второй верхушке
	other, err := spaceAdd(m, ph, "9"+hub.RandDigits(8), x)
	if err != nil {
		t.Fatal(err)
	}
	spSet(t, ca, cur)
	ob, _ := other.marshal()
	ca.SyncApply(ob, nil)
	if h := spaceHeadsOf(ca); len(h) != 2 {
		t.Fatalf("верхушек %d, ждали 2", len(h))
	}

	stranger, _, _ := ed25519.GenerateKey(nil)
	got := ca.SyncKeys()
	want := map[string]bool{string(cfgPub(cb)): true, string(keys[1]): true, string(x): true}
	if len(got) != len(want) {
		t.Errorf("SyncKeys: %d ключей, нужно %d", len(got), len(want))
	}
	for _, k := range got {
		if !want[string(k)] {
			t.Errorf("SyncKeys: лишний ключ %x", k[:4])
		}
	}
	for name, k := range map[string]ed25519.PublicKey{"свой": cfgPub(ca), "член": cfgPub(cb), "член 2": keys[1],
		"исключённый (во второй верхушке член)": keys[0], "только во второй верхушке": x, "посторонний": stranger} {
		if in := containsKey(got, k); in != ca.SyncKey(k) || in != want[string(k)] {
			t.Errorf("%s: в SyncKeys %v, SyncKey %v, нужно %v", name, in, ca.SyncKey(k), want[string(k)])
		}
	}

	spaceReset(t, ca, cur) // одна верхушка — только её члены
	if got := ca.SyncKeys(); len(got) != 2 || containsKey(got, x) || ca.SyncKey(x) {
		t.Errorf("одна верхушка: %d ключей, ключ второй %v", len(got), containsKey(got, x))
	}
}

func containsKey(l []ed25519.PublicKey, k []byte) bool {
	for _, x := range l {
		if bytes.Equal(x, k) {
			return true
		}
	}
	return false
}
