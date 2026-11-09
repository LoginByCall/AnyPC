package agent

import (
	"testing"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/rtp"
)

// TestPacer — кадр 50 × 1250 байт при 1 Мбит/с уходит за ≈ 50·10 000 бит / 2,5 Мбит/с = 200 мс, а не разом;
// после простоя запас не копится; без битрейта — без пауз.
func TestPacer(t *testing.T) {
	p := &pacer{}
	n := 0
	w := p.BindLocalStream(nil, interceptor.RTPWriterFunc(func(*rtp.Header, []byte, interceptor.Attributes) (int, error) { n++; return 0, nil }))
	payload := make([]byte, 1250-12)
	send := func(k int) time.Duration {
		t0 := time.Now()
		for range k {
			w.Write(&rtp.Header{}, payload, nil)
		}
		return time.Since(t0)
	}
	if d := send(50); d > 5*time.Millisecond || n != 50 {
		t.Fatalf("без битрейта: %v, %d пакетов", d, n)
	}
	p.kbps.Store(1000)
	if d := send(50); d < 180*time.Millisecond || d > 260*time.Millisecond {
		t.Fatalf("кадр 50 пакетов при 1 Мбит/с: %v, ждали ≈ 200 мс", d)
	}
	time.Sleep(300 * time.Millisecond) // простой: следующий кадр — снова в темпе, не пачкой «в долг»
	if d := send(50); d < 180*time.Millisecond {
		t.Fatalf("после простоя кадр ушёл за %v — запас накопился", d)
	}
}
