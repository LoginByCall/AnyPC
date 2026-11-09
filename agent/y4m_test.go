package agent

import (
	"bytes"
	"testing"
)

func TestY4M(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("YUV4MPEG2 W4 H2 F30000:1001 Ip A1:1 C420jpeg XYSCSS=420JPEG\n")
	for i := range 2 {
		b.WriteString("FRAME\n")
		b.Write(bytes.Repeat([]byte{byte(i)}, 4*2+2*2*1))
	}
	y, err := newY4M(&b)
	if err != nil || y.w != 4 || y.h != 2 || y.fps != 30 || len(y.frame) != 12 {
		t.Fatalf("%v %+v", err, y)
	}
	for i := range 2 {
		f, err := y.next()
		if err != nil || len(f) != 12 || f[0] != byte(i) || f[11] != byte(i) {
			t.Fatalf("кадр %d: %v %v", i, err, f)
		}
	}
	if _, err := y.next(); err == nil {
		t.Fatal("после конца потока нет ошибки")
	}
	if _, err := newY4M(bytes.NewBufferString("YUV4MPEG2 W4 H2 F30:1 C444\n")); err == nil {
		t.Fatal("4:4:4 принят")
	}
}
