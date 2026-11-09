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
// Оценка GCC по задержке пакетов из TWCC (без его контроллера потерь — потери учитывает эта же функция)
// режет раньше потерь: ниже 0.8 текущего два отчёта подряд — к оценке, но не круче ×0.6 за шаг
// (рабочий стол шлёт меньше потолка, и после разовой перегрузки GCC ставит 0.85 от реально принятого —
// на статичном экране это гораздо ниже доступной полосы); рост — не выше оценки и шагом не меньше +10 %.
// Каждый шаг перезапускает кодировщик (ffmpeg не меняет битрейт на лету): ~0.5 с паузы и новый IDR,
// поэтому шаги крупные и редкие.
// Качество кадра важнее плавности (решение владельца 2026-11-07): частота кадров падает вместе с битрейтом,
// бит на кадр остаётся прежним, пока частота не дойдёт до fpsMin; дальше снижается только битрейт.
type rate struct {
	max, cur   int  // кбит/с
	fpsMax     int  // кадров/с при max; 0 — частота не меняется
	video      bool // профиль «видео» (клиент, ctl quality): частота кадров не снижается, падает только битрейт
	fast       bool // кодер в процессе (VP9): шаг битрейта бесплатен — рост после rateHoldFast хорошего канала, а не 20 с
	low        int  // отчётов подряд с оценкой GCC ниже 0.8 текущего
	last, good time.Time
}

const (
	pliHold      = 2 * time.Second  // PLI раньше этого после старта захвата не перезапускает его (новый IDR ещё в пути)
	rateHold     = 20 * time.Second // столько без потерь до шага вверх, когда шаг = перезапуск ffmpeg (пауза и IDR)
	rateHoldFast = 3 * time.Second  // то же для кодера в процессе: 300 → 4000 кбит/с за ≈ 30 с, а не за 3 мин
	rateMin      = 300              // кбит/с — ниже картинка рабочего стола уже нечитаема
	fpsMin       = 5                // кадров/с — ниже курсор и ввод «прыгают»
)

// fps — частота кадров для текущего битрейта.
func (r *rate) fps() int {
	if r.fpsMax == 0 || r.max == 0 || r.video {
		return r.fpsMax
	}
	return max(fpsMin, min(r.fpsMax, (r.fpsMax*r.cur+r.max/2)/r.max))
}

// report учитывает долю потерь из отчёта и оценку GCC (кбит/с, 0 — нет);
// возвращает новый битрейт или 0 — без изменений.
func (r *rate) report(now time.Time, loss float64, est int) int {
	if est > 0 && est < r.cur*8/10 {
		r.low++
	} else {
		r.low = 0
	}
	switch {
	case loss > 0.10:
		r.good = time.Time{}
		if r.cur > rateMin && now.Sub(r.last) >= 3*time.Second {
			r.cur, r.last = max(r.cur*6/10, rateMin), now
			return r.cur
		}
	case r.low > 0:
		r.good = time.Time{}
		if n := max(est, r.cur*6/10, rateMin); r.low >= 2 && n < r.cur && now.Sub(r.last) >= 3*time.Second {
			r.cur, r.last = n, now
			return n
		}
	case loss < 0.02:
		if r.good.IsZero() {
			r.good = now
		}
		n := min(r.cur*13/10, r.max)
		if est > 0 {
			n = min(n, est)
		}
		hold := rateHold
		if r.fast {
			hold = rateHoldFast
		}
		if n >= r.cur*11/10 && now.Sub(r.good) >= hold && now.Sub(r.last) >= 3*time.Second {
			r.cur, r.last, r.good = n, now, now
			return n
		}
	default:
		r.good = time.Time{}
	}
	return 0
}

// setVideo — профиль «видео» (true) или «текст»; смена перезапускает захват (другие к/с и масштаб).
func (s *session) setVideo(v bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rate.video == v {
		return false
	}
	s.rate.video = v
	s.switched.Store(true)
	if s.capCancel != nil {
		s.capCancel()
	}
	return true
}

// onRTCP — отчёты клиента о приёме видео; при смене битрейта захват перезапускается сразу.
func (s *session) onRTCP(pkts []rtcp.Packet) {
	for _, p := range pkts {
		if _, ok := p.(*rtcp.TransportLayerCC); ok && s.bwe != nil && !s.twcc.Swap(true) {
			log.Printf("сессия %s: клиент шлёт TWCC — оценка полосы GCC работает", s.cid)
		}
		switch p.(type) {
		case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest: // клиент потерял опорный кадр
			if s.inproc.Load() { // кодер в процессе: ключевой кадр следующим, без перезапуска
				s.keyReq.Store(true)
				continue
			}
			s.mu.Lock()                                                  // ffmpeg: IDR даёт только новый процесс
			if time.Since(s.capStart) >= pliHold && s.capCancel != nil { // PLI в начале потока (до первого IDR) и шторм после потерь — один перезапуск
				log.Printf("сессия %s: PLI — перезапуск захвата ради IDR", s.cid)
				s.capStart = time.Now()
				s.switched.Store(true)
				s.capCancel()
			}
			s.mu.Unlock()
			continue
		}
		rr, ok := p.(*rtcp.ReceiverReport)
		if !ok {
			continue
		}
		for _, r := range rr.Reports {
			s.mu.Lock()
			if s.rate.max > 0 {
				est := 0
				if s.bwe != nil {
					est, _ = s.bwe.GetStats()["delayTargetBitrate"].(int)
					est /= 1000
				}
				if n := s.rate.report(time.Now(), float64(r.FractionLost)/256, est); n > 0 {
					log.Printf("сессия %s: битрейт %d кбит/с, %d к/с (потери %d %%, оценка GCC %d кбит/с)", s.cid, n, s.rate.fps(), int(r.FractionLost)*100/256, est)
					if s.pace != nil {
						s.pace.kbps.Store(int64(n))
					}
					if !s.inproc.Load() { // кодер в процессе применит сам; ffmpeg — только перезапуском
						s.switched.Store(true)
						if s.capCancel != nil {
							s.capCancel()
						}
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
