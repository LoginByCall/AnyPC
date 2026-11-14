package main

// Э4в: транспорт сверки без следа для хаба (agent/spseal.go) — ключи для перебора и джиттер пауз. Логика состава —
// app/spsync.go, здесь её не меняем.

import (
	"bytes"
	"crypto/ed25519"
	"math/rand/v2"
	"time"
)

// SyncKeys — agent.SpaceSyncer: все ключи, для которых SyncKey — true (члены объединения верхушек, кроме своего;
// исключённые в любой верхушке членами объединения не бывают); ими цель открывает запечатанное доказательство в
// connect.
func (c *config) SyncKeys() []ed25519.PublicKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	cur := c.spaceLocked()
	if cur == nil {
		return nil
	}
	var out []ed25519.PublicKey
	for _, x := range cur.Members {
		if c.syncMemberLocked(x.Pub) {
			out = append(out, bytes.Clone(x.Pub))
		}
	}
	return out
}

// syncJitter — d ± 50 %: хаб не узнаёт сверку по ровным паузам (раз в 10 мин, повторы 1, 2, 4… с).
func syncJitter(d time.Duration) time.Duration {
	return d/2 + rand.N(d+1)
}
