package main

// Э4в: транспорт сверки без следа для хаба (agent/spseal.go) — ключи для перебора и джиттер пауз. Логика состава —
// app/spsync.go, здесь её не меняем.

import (
	"bytes"
	"crypto/ed25519"
	"math/rand/v2"
	"time"
)

// SyncKeys — agent.SpaceSyncer: все ключи, для которых SyncKey — true (члены M и ветви раскола, кроме своего и
// исключённых); ими цель открывает запечатанное доказательство в connect.
func (c *config) SyncKeys() []ed25519.PublicKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	cur := c.spaceLocked()
	if cur == nil {
		return nil
	}
	ms := cur.Members
	if f, _ := spaceParse(c.SpaceFork); f != nil && cur.sameSpace(f) {
		ms = append(ms[:len(ms):len(ms)], f.Members...)
	}
	me := ed25519.PrivateKey(c.Key).Public().(ed25519.PublicKey)
	var out []ed25519.PublicKey
	for _, x := range ms {
		if !cur.gone(x.Pub) && !bytes.Equal(x.Pub, me) && !containsKey(out, x.Pub) {
			out = append(out, bytes.Clone(x.Pub))
		}
	}
	return out
}

func containsKey(l []ed25519.PublicKey, k []byte) bool {
	for _, x := range l {
		if bytes.Equal(x, k) {
			return true
		}
	}
	return false
}

// syncJitter — d ± 50 %: хаб не узнаёт сверку по ровным паузам (раз в 10 мин, повторы 1, 2, 4… с).
func syncJitter(d time.Duration) time.Duration {
	return d/2 + rand.N(d+1)
}
