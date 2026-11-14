package main

import (
	"crypto/ed25519"
	"testing"

	"anypc/hub"
	"anypc/totp"
)

// TestSpaceSyncKeys — Э4в: SyncKeys (ими цель открывает sx connect) — ровно те ключи, для которых SyncKey — true, на
// одном составе с исключённым, своим ключом и ветвью раскола: члены M и ветви, кроме своего и исключённых в M (даже
// если в ветви он ещё член), без повторов.
func TestSpaceSyncKeys(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 2, ca, cb) // keys[0] исключим в M, keys[1] — член
	m := spaceOf(ca)
	cur, err := spaceRemove(m, ph, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	x, _, _ := ed25519.GenerateKey(nil) // только в ветви раскола
	fork, err := spaceAdd(m, ph, "9"+hub.RandDigits(8), x)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := fork.marshal()
	ca.mu.Lock()
	ca.Space = nil
	if _, err := ca.spaceSetLocked(cur); err != nil {
		t.Fatal(err)
	}
	ca.SpaceFork = raw
	ca.save()
	ca.mu.Unlock()

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
		"исключённый (в ветви член)": keys[0], "только в ветви": x, "посторонний": stranger} {
		if in := containsKey(got, k); in != ca.SyncKey(k) || in != want[string(k)] {
			t.Errorf("%s: в SyncKeys %v, SyncKey %v, нужно %v", name, in, ca.SyncKey(k), want[string(k)])
		}
	}

	ca.mu.Lock() // без ветви раскола — только члены M
	ca.SpaceFork = nil
	ca.save()
	ca.mu.Unlock()
	if got := ca.SyncKeys(); len(got) != 2 || containsKey(got, x) || ca.SyncKey(x) {
		t.Errorf("без раскола: %d ключей, ключ ветви %v", len(got), containsKey(got, x))
	}
}
