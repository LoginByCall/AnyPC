package agent

import (
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/pion/rtcp"
)

// rate — адаптивный битрейт (REQ-N-03) по RTCP Receiver Report клиента (~1 раз в секунду):
// потери > 10 % — ×0.6 сразу (не чаще раза в 3 с); < 2 % двадцать секунд подряд — ×1.3 до потолка.
// Каждый шаг перезапускает кодировщик (ffmpeg не меняет битрейт на лету): ~0.5 с паузы и новый IDR,
// поэтому шаги крупные и редкие.
// ponytail: только потери, без оценки по задержке (GCC); добавить RTT/jitter, если очередь растёт без потерь.
type rate struct {
	max, cur   int // кбит/с
	last, good time.Time
}

const rateMin = 300 // кбит/с — ниже картинка рабочего стола уже нечитаема

// report учитывает долю потерь из отчёта; возвращает новый битрейт или 0 — без изменений.
func (r *rate) report(now time.Time, loss float64) int {
	switch {
	case loss > 0.10:
		r.good = time.Time{}
		if r.cur > rateMin && now.Sub(r.last) >= 3*time.Second {
			r.cur, r.last = max(r.cur*6/10, rateMin), now
			return r.cur
		}
	case loss < 0.02:
		if r.good.IsZero() {
			r.good = now
		}
		if r.cur < r.max && now.Sub(r.good) >= 20*time.Second && now.Sub(r.last) >= 3*time.Second {
			r.cur, r.last, r.good = min(r.cur*13/10, r.max), now, now
			return r.cur
		}
	default:
		r.good = time.Time{}
	}
	return 0
}

// onRTCP — отчёты клиента о приёме видео; при смене битрейта захват перезапускается сразу.
func (s *session) onRTCP(pkts []rtcp.Packet) {
	for _, p := range pkts {
		rr, ok := p.(*rtcp.ReceiverReport)
		if !ok {
			continue
		}
		for _, r := range rr.Reports {
			s.mu.Lock()
			if s.rate.max > 0 {
				if n := s.rate.report(time.Now(), float64(r.FractionLost)/256); n > 0 {
					log.Printf("сессия %s: битрейт %d кбит/с (потери %d %%)", s.cid, n, int(r.FractionLost)*100/256)
					s.switched.Store(true)
					if s.capCancel != nil {
						s.capCancel()
					}
				}
			}
			s.mu.Unlock()
		}
	}
}

// Kbps — "4M", "1500k", "800" → кбит/с; ошибка → 4000.
func Kbps(br string) int {
	m := 1
	switch {
	case strings.HasSuffix(br, "M"):
		m, br = 1000, strings.TrimSuffix(br, "M")
	case strings.HasSuffix(br, "k"):
		br = strings.TrimSuffix(br, "k")
	}
	n, err := strconv.Atoi(br)
	if err != nil || n <= 0 {
		return 4000
	}
	return n * m
}
