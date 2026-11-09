package agent

import (
	"testing"
	"time"

	"github.com/pion/rtcp"
)

// TestRate — REQ-N-03: потери режут битрейт сразу, но не чаще раза в 3 с и не ниже rateMin;
// рост — только после 20 с чистого канала и не выше потолка; средние потери копят «чистое» время заново.
func TestRate(t *testing.T) {
	t0 := time.Unix(1000, 0)
	at := func(s float64) time.Time { return t0.Add(time.Duration(s * float64(time.Second))) }
	r := rate{max: 4000, cur: 4000}
	steps := []struct {
		s    float64
		loss float64
		want int
	}{
		{0, 0.30, 2400},  // сильные потери — вниз сразу
		{1, 0.30, 0},     // кулдаун 3 с
		{3, 0.30, 1440},  // снова вниз
		{4, 0.0, 0},      // чисто — начало отсчёта
		{20, 0.05, 0},    // средние потери — отсчёт сброшен
		{21, 0.0, 0},     // заново
		{40, 0.0, 0},     // 19 с — рано
		{41, 0.0, 1872},  // 20 с чисто — вверх ×1.3
		{61, 0.0, 2433},  // ещё 20 с
		{81, 0.0, 3162},  // ...
		{101, 0.0, 4000}, // упёрлись в потолок
		{121, 0.0, 0},    // выше не растёт
	}
	for _, st := range steps {
		if got := r.report(at(st.s), st.loss, 0); got != st.want {
			t.Fatalf("t=%vs loss=%v: %d, ждали %d", st.s, st.loss, got, st.want)
		}
	}
	r = rate{max: 400, cur: 400}
	for i := range 10 {
		r.report(at(float64(i*3)), 1, 0)
	}
	if r.cur != rateMin {
		t.Fatalf("ниже минимума: %d", r.cur)
	}
	if Kbps("4M") != 4000 || Kbps("1500k") != 1500 || Kbps("x") != 4000 {
		t.Fatal("Kbps")
	}
}

// TestRateRestartsCapture — отчёт RR с потерями перезапускает захват с новым битрейтом; выключенная адаптация молчит.
func TestRateRestartsCapture(t *testing.T) {
	cancelled := 0
	s := &session{cid: "c1", rate: rate{max: 4000, cur: 4000}, capCancel: func() { cancelled++ }}
	rr := []rtcp.Packet{&rtcp.ReceiverReport{Reports: []rtcp.ReceptionReport{{SSRC: 1, FractionLost: 128}}}} // 50 %
	s.onRTCP(rr)
	if s.rate.cur != 2400 || cancelled != 1 || !s.switched.Load() {
		t.Fatalf("cur=%d cancel=%d switched=%v", s.rate.cur, cancelled, s.switched.Load())
	}
	off := &session{capCancel: func() { cancelled++ }}
	off.onRTCP(rr)
	if cancelled != 1 || off.switched.Load() {
		t.Fatal("адаптация без потолка (тестовый FF) не должна трогать захват")
	}
	// кодер в процессе: битрейт меняется в rate, PLI → keyReq, захват не трогается
	in := &session{cid: "c2", rate: rate{max: 4000, cur: 4000}, capCancel: func() { cancelled++ }, capStart: time.Now().Add(-time.Minute)}
	in.inproc.Store(true)
	in.onRTCP(rr)
	in.onRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{}})
	if in.rate.cur != 2400 || cancelled != 1 || in.switched.Load() || !in.keyReq.Load() {
		t.Fatalf("в процессе: cur=%d cancel=%d switched=%v keyReq=%v", in.rate.cur, cancelled, in.switched.Load(), in.keyReq.Load())
	}
}

// TestRateFPS — качество кадра важнее плавности: частота падает пропорционально битрейту (бит на кадр — как при max),
// не ниже fpsMin; дальше падает только битрейт. Рост — обратно до fpsMax.
func TestRateFPS(t *testing.T) {
	r := rate{max: 4000, cur: 4000, fpsMax: 30}
	want := []struct{ kbps, fps int }{{4000, 30}, {2400, 18}, {1440, 11}, {864, 6}, {518, 5}, {310, 5}, {300, 5}}
	for i, w := range want {
		if i > 0 {
			r.report(time.Unix(int64(1000+i*3), 0), 0.5, 0)
		}
		if r.cur != w.kbps || r.fps() != w.fps {
			t.Fatalf("шаг %d: %d кбит/с %d к/с, ждали %d/%d", i, r.cur, r.fps(), w.kbps, w.fps)
		}
	}
	if (&rate{max: 4000, cur: 4000}).fps() != 0 || (&rate{fpsMax: 30}).fps() != 30 {
		t.Fatal("без адаптации частота не должна меняться")
	}
}

// TestRateGCC — оценка GCC по задержке (рост очереди) режет битрейт до потерь: только подтверждённая двумя
// отчётами подряд и не круче ×0.6 за шаг (разовый всплеск чужого трафика не роняет до минимума);
// рост — не выше оценки и шагом не меньше +10 % (перезапуск кодировщика ради 1 кбит/с не нужен).
func TestRateGCC(t *testing.T) {
	t0 := time.Unix(1000, 0)
	at := func(s float64) time.Time { return t0.Add(time.Duration(s * float64(time.Second))) }
	r := rate{max: 4000, cur: 4000}
	steps := []struct {
		s         float64
		loss      float64
		est, want int
	}{
		{0, 0, 3500, 0},     // чуть ниже текущего — не трогаем
		{1, 0, 1000, 0},     // низкая один раз — ждём подтверждения
		{2, 0, 3500, 0},     // не подтвердилась — счётчик сброшен
		{3, 0, 1000, 0},     // снова один раз
		{4, 0, 1000, 2400},  // два отчёта подряд — вниз, но не круче ×0.6
		{5, 0, 1000, 0},     // кулдаун 3 с
		{7, 0, 1000, 1440},  // ещё ×0.6
		{10, 0, 1000, 1000}, // до оценки
		{13, 0, 100, 600},   // ниже — снова не круче ×0.6
		{16, 0, 100, 360},
		{19, 0, 100, 300},  // не ниже rateMin
		{22, 0, 100, 0},    // уже на минимуме
		{23, 0, 4000, 0},   // канал свободен — отсчёт чистых 20 с
		{43, 0, 320, 0},    // ×1.3 ограничен оценкой 320, это меньше +10 % — не перезапускаем
		{44, 0, 4000, 390}, // оценка выросла — обычный шаг ×1.3
		{64, 0, 4000, 507},
		{68, 0.30, 4000, 304}, // потери — как раньше (×0.6)
	}
	for _, st := range steps {
		if got := r.report(at(st.s), st.loss, st.est); got != st.want {
			t.Fatalf("t=%vs loss=%v est=%d: %d, ждали %d", st.s, st.loss, st.est, got, st.want)
		}
	}
}
