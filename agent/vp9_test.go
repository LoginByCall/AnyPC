//go:build vp9

package agent

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestVP9 — кодер в процессе: первый кадр ключевой, дальше нет; смена битрейта без ключевого; ключевой по запросу.
func TestVP9(t *testing.T) {
	w, h := 320, 240
	e, err := newVP9(w, h, 500)
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	frame := make([]byte, w*h*3/2)
	for i := range frame {
		frame[i] = byte(i)
	}
	var sizes []int
	for i := range 10 {
		frame[i*64] ^= 0xff // немного движения
		out, key, err := e.encode(frame, 33*time.Millisecond, false)
		if err != nil || len(out) == 0 || key != (i == 0) {
			t.Fatalf("кадр %d: %v, %d байт, key=%v", i, err, len(out), key)
		}
		sizes = append(sizes, len(out))
	}
	if err := e.setRate(200, 30); err != nil {
		t.Fatal(err)
	}
	if _, key, err := e.encode(frame, 33*time.Millisecond, false); err != nil || key {
		t.Fatalf("после смены битрейта: %v key=%v", err, key)
	}
	if _, key, err := e.encode(frame, 33*time.Millisecond, true); err != nil || !key {
		t.Fatalf("принудительный ключевой: %v key=%v", err, key)
	}
	if _, _, err := e.encode(frame[:10], 33*time.Millisecond, false); err == nil {
		t.Fatal("кадр неверного размера принят")
	}
	t.Logf("размеры кадров: %v", sizes)
}

// BenchmarkVP9 — 1080p, синтетическое движение (бегущая полоса на шуме): CPU на кадр при настройках хоста.
func BenchmarkVP9(b *testing.B) {
	w, h := 1920, 1080
	e, err := newVP9(w, h, 4000)
	if err != nil {
		b.Fatal(err)
	}
	defer e.close()
	frame := make([]byte, w*h*3/2)
	for i := range frame {
		frame[i] = byte(i * 7)
	}
	b.ResetTimer()
	total := 0
	for i := 0; b.Loop(); i++ {
		x := (i * 16) % w
		for y := 0; y < h; y++ {
			frame[y*w+x] = 0xff
		}
		out, _, err := e.encode(frame, 33*time.Millisecond, false)
		if err != nil {
			b.Fatal(err)
		}
		total += len(out)
	}
	b.ReportMetric(float64(total)*8/1000/float64(b.N)*30, "kbit/s")
}

// TestVP9Bench — замерный стенд (не в обычном прогоне): ANYPC_VP9_Y4M=файл.y4m ANYPC_VP9_RUN="kbps,fps,aq,keyms,cq,cbr,drop,interms"
// ANYPC_VP9_OUT=файл.ivf — кодирует тем же кодом, что программа (прореживание до fps, setRate на кадре), пишет IVF
// и размеры кадров; PSNR по кадрам считает ffmpeg (см. LOGBOOK).
func TestVP9Bench(t *testing.T) {
	in, out := os.Getenv("ANYPC_VP9_Y4M"), os.Getenv("ANYPC_VP9_OUT")
	if in == "" || out == "" {
		t.Skip("ANYPC_VP9_Y4M/ANYPC_VP9_OUT не заданы")
	}
	p := strings.Split(os.Getenv("ANYPC_VP9_RUN"), ",")
	n := func(i, def int) int {
		if i < len(p) {
			if v, err := strconv.Atoi(p[i]); err == nil {
				return v
			}
		}
		return def
	}
	kbps, fps := n(0, 1000), n(1, 30)
	vp9Opt.AQ, vp9Opt.KeyMs, vp9Opt.CQ, vp9Opt.CBR, vp9Opt.Drop, vp9Opt.InterMs = n(2, vp9Opt.AQ), n(3, vp9Opt.KeyMs), n(4, vp9Opt.CQ), n(5, vp9Opt.CBR), n(6, vp9Opt.Drop), n(7, vp9Opt.InterMs)
	vp9Opt.MinQ = n(8, vp9Opt.MinQ)
	f, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	y, err := newY4M(f)
	if err != nil {
		t.Fatal(err)
	}
	e, err := newVP9(y.w, y.h, kbps)
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	o, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	hdr := make([]byte, 32) // IVF: DKIF, версия 0, длина заголовка 32, VP90, w, h, частота/шкала, число кадров
	copy(hdr, "DKIF")
	binary.LittleEndian.PutUint16(hdr[6:], 32)
	copy(hdr[8:], "VP90")
	binary.LittleEndian.PutUint16(hdr[12:], uint16(y.w))
	binary.LittleEndian.PutUint16(hdr[14:], uint16(y.h))
	binary.LittleEndian.PutUint32(hdr[16:], uint32(fps))
	binary.LittleEndian.PutUint32(hdr[20:], 1)
	o.Write(hdr)
	var sizes []string
	acc, k, start := 0.0, 0, time.Now()
	for {
		frame, err := y.next()
		if err != nil {
			break
		}
		if acc += float64(fps) / float64(y.fps); acc < 1 {
			continue
		}
		acc--
		if err := e.setRate(kbps, fps); err != nil {
			t.Fatal(err)
		}
		data, _, err := e.encode(frame, time.Second/time.Duration(fps), false)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 { // кадр пропущен кодером (Drop): в IVF — повтор нельзя, пишем как есть, размер 0
			sizes = append(sizes, "0")
			k++
			continue
		}
		fh := make([]byte, 12)
		binary.LittleEndian.PutUint32(fh, uint32(len(data)))
		binary.LittleEndian.PutUint64(fh[4:], uint64(k))
		o.Write(fh)
		o.Write(data)
		sizes = append(sizes, strconv.Itoa(len(data)))
		k++
	}
	os.WriteFile(out+".sizes", []byte(strings.Join(sizes, "\n")+"\n"), 0o644)
	fmt.Printf("кадров %d за %v (%.1f мс/кадр)\n", k, time.Since(start), float64(time.Since(start).Milliseconds())/float64(max(k, 1)))
}
