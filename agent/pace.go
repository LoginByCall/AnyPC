package agent

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/rtp"
)

// pacer — интерсептор на выходе видео: пакеты кадра уходят не пачкой, а с темпом paceFactor × текущего битрейта
// (как pacing factor у libwebrtc). Без него кадр в сотню пакетов разом переполняет буфер приёма UDP у клиента:
// замер 2026-11-10 (LOGBOOK, FINDINGS) — пачка 400 × 1,2 КБ Мак → Linux теряет 20–30 % при буфере 208 КБ, с тем же
// буфером в темпе 10 Мбит/с — 0 %; контроллер принимал это за перегрузку канала и резал поток до 300 кбит/с.
// Регистрируется последним (ближе всех к приложению): TWCC/GCC ниже видят фактическое время отправки.
// Пейсер pion (gcc.LeakyBucketPacer) не подошёл: копит бюджет в простое и выпускает кадр той же пачкой.
type pacer struct {
	interceptor.NoOp
	kbps atomic.Int64 // текущий битрейт сессии; 0 — без темпа (адаптация выключена)
	mu   sync.Mutex
	next time.Time // когда можно отправить следующий байт
}

const (
	paceFactor = 2.5
	paceSlack  = 2 * time.Millisecond // пачка короче этого уходит без паузы: точнее таймер не спит
)

func (p *pacer) NewInterceptor(string) (interceptor.Interceptor, error) { return p, nil }

func (p *pacer) BindLocalStream(_ *interceptor.StreamInfo, w interceptor.RTPWriter) interceptor.RTPWriter {
	return interceptor.RTPWriterFunc(func(h *rtp.Header, payload []byte, a interceptor.Attributes) (int, error) {
		p.wait(h.MarshalSize() + len(payload))
		return w.Write(h, payload, a)
	})
}

// wait — пауза перед пакетом в n байт: ведро с выходом paceFactor × kbps, запас в простое не копится.
// Спит поток кодера: отставание по сети тормозит захват, а не растит очередь.
func (p *pacer) wait(n int) {
	k := p.kbps.Load()
	if k <= 0 {
		return
	}
	p.mu.Lock()
	now := time.Now()
	if p.next.Before(now) {
		p.next = now
	}
	d := p.next.Sub(now)
	p.next = p.next.Add(time.Duration(float64(n*8) / (paceFactor * float64(k) * 1000) * float64(time.Second)))
	p.mu.Unlock()
	if d > paceSlack {
		time.Sleep(d)
	}
}
