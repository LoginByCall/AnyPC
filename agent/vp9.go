//go:build vp9

package agent

// Кодер VP9 в процессе (libvpx, статически; сборка с -tags vp9, библиотеки — deploy/libvpx.sh). Зачем не ffmpeg:
// битрейт, частота кадров и ключевой кадр меняются на лету без перезапуска процесса (у ffmpeg каждый шаг — пауза
// ~0,5 с и новый IDR), а VP9 с tune-content=screen на тексте дорисовывает статику вдвое быстрее x264 и на движении
// даёт +1 дБ при 72 % битрейта (LOGBOOK 2026-11-09).

/*
#cgo LDFLAGS: -lvpx -lm
#cgo !darwin LDFLAGS: -lpthread
#include <stdlib.h>
#include <string.h>
#include <vpx/vpx_encoder.h>
#include <vpx/vp8cx.h>

static vpx_codec_err_t anyctl(vpx_codec_ctx_t *c, int id, int v) { return vpx_codec_control_(c, id, v); }

// anyenc — закодировать img и вернуть сжатый кадр (память libvpx, действительна до следующего вызова);
// *sz == 0 — кадр пропущен кодером (rc_dropframe_thresh > 0: буфер пуст).
static vpx_codec_err_t anyenc(vpx_codec_ctx_t *c, vpx_image_t *img, vpx_codec_pts_t pts, unsigned long dur, long flags,
                              const void **out, size_t *sz, int *key) {
	*out = NULL; *sz = 0; *key = 0;
	vpx_codec_err_t e = vpx_codec_encode(c, img, pts, dur, flags, VPX_DL_REALTIME);
	if (e) return e;
	vpx_codec_iter_t it = NULL;
	const vpx_codec_cx_pkt_t *p;
	while ((p = vpx_codec_get_cx_data(c, &it)))
		if (p->kind == VPX_CODEC_CX_FRAME_PKT) {
			*out = p->data.frame.buf; *sz = p->data.frame.sz; *key = (p->data.frame.flags & VPX_FRAME_IS_KEY) != 0;
			return 0;
		}
	return 0;
}
*/
import "C"

import (
	"fmt"
	"runtime"
	"time"
	"unsafe"
)

// VP9Built — программа собрана с кодером VP9.
const VP9Built = true

type vp9 struct {
	ctx  *C.vpx_codec_ctx_t
	cfg  *C.vpx_codec_enc_cfg_t
	img  *C.vpx_image_t
	buf  unsafe.Pointer // кадр I420 в памяти C: libvpx держит указатель между вызовами
	n    int
	pts  C.vpx_codec_pts_t
	kbps int
	fps  int
}

// vp9Opt — ручки кодера (замерный стенд: TestVP9Bench в vp9_test.go, ANYPC_VP9_Y4M). CQ — целевое качество (как CRF
// у x264): к нему дорисовывается статика, выше потолка битрейта не выходит; AQ — режим адаптивного квантования
// (3 — циклическое обновление статичных блоков); KeyMs — потолок ключевого кадра в мс потока на текущем битрейте
// (как у libwebrtc: 0,5 × оптимального буфера 600 мс; 0 — без потолка) — большой ключевой кадр пачкой переполняет буфер приёма.
// Значения по замеру 2026-11-10 (LOGBOOK, FINDINGS): CBR (CBR=1) — единственный режим libvpx, где размер кадра
// держится: в CQ смена картинки даёт кадр в 15–42 средних (110–175 КБ), потолок обычного кадра CQ не слушает.
// MinQ 10 — предел дорисовки (≈ 50 дБ на тексте): с MinQ 2 CBR тратит 1–1,3 Мбит/с на статике, с 10 — 80 кбит/с
// (REQ-N-05 ≤ 200). Drop — пропуск кадров при пустом буфере: на смене текста только замедлял дорисовку.
var vp9Opt = struct{ CQ, AQ, CPU, KeyMs, InterMs, CBR, Drop, MinQ int }{CQ: 20, AQ: 3, CPU: 8, KeyMs: 300, CBR: 1, MinQ: 10}

// newVP9 — кодер w×h, потолок kbps, режим реального времени для экрана.
func newVP9(w, h, kbps int) (*vp9, error) {
	e := &vp9{
		ctx: (*C.vpx_codec_ctx_t)(C.calloc(1, C.sizeof_vpx_codec_ctx_t)),
		cfg: (*C.vpx_codec_enc_cfg_t)(C.calloc(1, C.sizeof_vpx_codec_enc_cfg_t)),
		img: (*C.vpx_image_t)(C.calloc(1, C.sizeof_vpx_image_t)),
		n:   w*h + 2*((w+1)/2)*((h+1)/2), kbps: kbps,
	}
	iface := C.vpx_codec_vp9_cx()
	if r := C.vpx_codec_enc_config_default(iface, e.cfg, 0); r != 0 {
		e.close()
		return nil, fmt.Errorf("vp9: config_default: %d", r)
	}
	c := e.cfg
	c.g_w, c.g_h = C.uint(w), C.uint(h)
	c.g_timebase.num, c.g_timebase.den = 1, 1000 // pts в мс
	c.g_threads = C.uint(min(4, runtime.NumCPU()))
	c.g_lag_in_frames = 0
	c.g_error_resilient = C.VPX_ERROR_RESILIENT_DEFAULT
	c.rc_end_usage = C.VPX_CQ // качество vp9Opt.CQ при потолке rc_target_bitrate — как CRF + VBV
	if vp9Opt.CBR != 0 {
		c.rc_end_usage = C.VPX_CBR
	}
	c.rc_target_bitrate = C.uint(kbps)
	c.rc_min_quantizer, c.rc_max_quantizer = C.uint(vp9Opt.MinQ), 56
	c.rc_buf_sz, c.rc_buf_initial_sz, c.rc_buf_optimal_sz = 1000, 500, 600 // мс
	c.rc_undershoot_pct, c.rc_overshoot_pct = 50, 50
	c.rc_dropframe_thresh = C.uint(vp9Opt.Drop) // > 0 — кодер пропускает кадр, когда буфер пуст, вместо перерасхода
	c.kf_mode = C.VPX_KF_DISABLED               // ключевые — первый и по запросу (PLI)
	if r := C.vpx_codec_enc_init_ver(e.ctx, iface, e.cfg, 0, C.VPX_ENCODER_ABI_VERSION); r != 0 {
		err := fmt.Errorf("vp9: init: %s", C.GoString(C.vpx_codec_error(e.ctx)))
		e.close()
		return nil, err
	}
	for _, kv := range [][2]C.int{
		{C.VP8E_SET_CPUUSED, C.int(vp9Opt.CPU)}, // реальное время для 1080p; замер: ~1 ядро на 1080p30 (LOGBOOK 2026-11-09)
		{C.VP9E_SET_ROW_MT, 1}, {C.VP9E_SET_TILE_COLUMNS, 2},
		{C.VP9E_SET_TUNE_CONTENT, C.VP9E_CONTENT_SCREEN},
		{C.VP9E_SET_AQ_MODE, C.int(vp9Opt.AQ)},
		{C.VP8E_SET_CQ_LEVEL, C.int(vp9Opt.CQ)},
	} {
		if r := C.anyctl(e.ctx, kv[0], kv[1]); r != 0 {
			err := fmt.Errorf("vp9: control %d: %s", kv[0], C.GoString(C.vpx_codec_error(e.ctx)))
			e.close()
			return nil, err
		}
	}
	e.buf = C.malloc(C.size_t(e.n))
	C.vpx_img_wrap(e.img, C.VPX_IMG_FMT_I420, C.uint(w), C.uint(h), 1, (*C.uchar)(e.buf))
	return e, nil
}

// setRate — новый потолок и частота кадров без перезапуска и без ключевого кадра; потолок ключевого кадра —
// vp9Opt.KeyMs потока (в процентах от среднего кадра при fps, не ниже 300 %, как у libwebrtc).
func (e *vp9) setRate(kbps, fps int) error {
	if kbps != e.kbps {
		e.cfg.rc_target_bitrate = C.uint(kbps)
		if r := C.vpx_codec_enc_config_set(e.ctx, e.cfg); r != 0 {
			return fmt.Errorf("vp9: битрейт %d: %s", kbps, C.GoString(C.vpx_codec_error(e.ctx)))
		}
		e.kbps = kbps
	}
	if fps != e.fps && fps > 0 && vp9Opt.KeyMs > 0 {
		if r := C.anyctl(e.ctx, C.VP8E_SET_MAX_INTRA_BITRATE_PCT, C.int(max(300, vp9Opt.KeyMs*fps/10))); r != 0 {
			return fmt.Errorf("vp9: потолок ключевого кадра: %s", C.GoString(C.vpx_codec_error(e.ctx)))
		}
	}
	if fps != e.fps && fps > 0 && vp9Opt.InterMs > 0 { // то же для обычных кадров: смена картинки в CQ иначе — до 40 средних кадров
		if r := C.anyctl(e.ctx, C.VP9E_SET_MAX_INTER_BITRATE_PCT, C.int(max(100, vp9Opt.InterMs*fps/10))); r != 0 {
			return fmt.Errorf("vp9: потолок кадра: %s", C.GoString(C.vpx_codec_error(e.ctx)))
		}
	}
	if fps > 0 {
		e.fps = fps
	}
	return nil
}

// encode — кадр I420 (len == n) длительностью dur; key — принудительно ключевой. Возвращает сжатый кадр (копия);
// nil без ошибки — кодер пропустил кадр (vp9Opt.Drop), у клиента остаётся предыдущий.
func (e *vp9) encode(frame []byte, dur time.Duration, key bool) (out []byte, isKey bool, err error) {
	if len(frame) != e.n {
		return nil, false, fmt.Errorf("vp9: кадр %d байт, ждали %d", len(frame), e.n)
	}
	C.memcpy(e.buf, unsafe.Pointer(&frame[0]), C.size_t(e.n))
	var flags C.long
	if key {
		flags = C.VPX_EFLAG_FORCE_KF
	}
	ms := C.ulong(max(1, dur.Milliseconds()))
	var p unsafe.Pointer
	var sz C.size_t
	var k C.int
	if r := C.anyenc(e.ctx, e.img, e.pts, ms, flags, &p, &sz, &k); r != 0 {
		return nil, false, fmt.Errorf("vp9: encode: %s", C.GoString(C.vpx_codec_error(e.ctx)))
	}
	e.pts += C.vpx_codec_pts_t(ms)
	if sz == 0 {
		return nil, false, nil
	}
	return C.GoBytes(p, C.int(sz)), k != 0, nil
}

func (e *vp9) close() {
	if e.buf != nil {
		C.vpx_codec_destroy(e.ctx)
		C.free(e.buf)
	}
	C.free(unsafe.Pointer(e.img))
	C.free(unsafe.Pointer(e.cfg))
	C.free(unsafe.Pointer(e.ctx))
	e.buf = nil
}
