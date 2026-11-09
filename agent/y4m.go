package agent

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// y4m — поток YUV4MPEG2 (ffmpeg -f yuv4mpegpipe): заголовок «YUV4MPEG2 W1920 H1080 F30:1 … C420…», затем
// кадры «FRAME\n» + w×h×3/2 байт I420. Только 4:2:0 8 бит — то, что просим у ffmpeg (-pix_fmt yuv420p).
type y4m struct {
	r        *bufio.Reader
	w, h     int
	fps      int // кадров/с источника (округлённо)
	frame    []byte
	chromaSz int
}

func newY4M(r io.Reader) (*y4m, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("y4m: заголовок: %w", err)
	}
	f := strings.Fields(line)
	if len(f) == 0 || f[0] != "YUV4MPEG2" {
		return nil, errors.New("y4m: не YUV4MPEG2")
	}
	y := &y4m{r: br, fps: 30}
	for _, t := range f[1:] {
		switch t[0] {
		case 'W':
			y.w, _ = strconv.Atoi(t[1:])
		case 'H':
			y.h, _ = strconv.Atoi(t[1:])
		case 'F':
			if n, d, ok := strings.Cut(t[1:], ":"); ok {
				num, _ := strconv.Atoi(n)
				den, _ := strconv.Atoi(d)
				if den > 0 && num > 0 {
					y.fps = (num + den/2) / den
				}
			}
		case 'C':
			if !strings.HasPrefix(t, "C420") {
				return nil, fmt.Errorf("y4m: формат %s, нужен 4:2:0", t)
			}
		}
	}
	if y.w < 2 || y.h < 2 {
		return nil, errors.New("y4m: нет размера кадра")
	}
	y.chromaSz = ((y.w + 1) / 2) * ((y.h + 1) / 2)
	y.frame = make([]byte, y.w*y.h+2*y.chromaSz)
	return y, nil
}

// next — следующий кадр I420; буфер общий, действителен до следующего вызова.
func (y *y4m) next() ([]byte, error) {
	line, err := y.r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, "FRAME") {
		return nil, fmt.Errorf("y4m: ждали FRAME, пришло %q", strings.TrimSpace(line))
	}
	if _, err := io.ReadFull(y.r, y.frame); err != nil {
		return nil, err
	}
	return y.frame, nil
}
