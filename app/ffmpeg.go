package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FFmpeg для Windows не вшит в AnyPC.exe: при первом запуске программа берёт ffmpeg.exe из официальной
// сборки gyan.dev (GPLv3, распространяет gyan.dev). Из zip по HTTP Range читается только ffmpeg.exe
// (~40 из 115 МБ); SHA-256 закреплён — с зеркала не придёт ничего, кроме проверенной сборки.
var (
	ffMirrors = []string{
		// оба — от автора сборки (GyanD); GitHub первым: из России 25 с против 6 мин 44 с у gyan.dev (замер 2026-11-07)
		"https://github.com/GyanD/codexffmpeg/releases/download/9.0.2/ffmpeg-9.0.2-essentials_build.zip",
		"https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-9.0.2-essentials_build.zip",
	}
	ffEntry  = "ffmpeg-9.0.2-essentials_build/bin/ffmpeg.exe"
	ffSHA256 = "3256173f3f8bffd7df12227c68adf68025edb1832273a9530688a7bb1ed8edec"
)

// ensureFFmpeg — путь к проверенному ffmpeg.exe в dir; нет — скачать с первого живого зеркала.
// progress(done, total) — байты распакованного файла.
func ensureFFmpeg(dir string, progress func(done, total int64)) (string, error) {
	p := filepath.Join(dir, "ffmpeg-"+ffSHA256[:12]+".exe")
	if _, err := os.Stat(p); err == nil { // пишется только после проверки хэша
		return p, nil
	}
	var errs []string
	for _, u := range ffMirrors {
		err := fetchEntry(u, p, progress)
		if err == nil {
			return p, nil
		}
		errs = append(errs, err.Error())
	}
	return "", errors.New(strings.Join(errs, "; "))
}

func fetchEntry(u, dst string, progress func(done, total int64)) error {
	ra := &httpReaderAt{url: u}
	size, err := ra.size()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return fmt.Errorf("%s: %w", u, err)
	}
	for _, f := range zr.File {
		if f.Name != ffEntry {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		tmp := dst + ".tmp"
		out, err := os.Create(tmp)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(io.MultiWriter(out, h, &counter{total: int64(f.UncompressedSize64), fn: progress}), rc)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err == nil && hex.EncodeToString(h.Sum(nil)) != ffSHA256 {
			err = fmt.Errorf("%s: SHA-256 не совпал", u)
		}
		if err != nil {
			os.Remove(tmp)
			return err
		}
		return os.Rename(tmp, dst)
	}
	return fmt.Errorf("%s: нет %s в архиве", u, ffEntry)
}

type counter struct {
	done, total int64
	fn          func(done, total int64)
}

func (c *counter) Write(b []byte) (int, error) {
	c.done += int64(len(b))
	if c.fn != nil {
		c.fn(c.done, c.total)
	}
	return len(b), nil
}

// httpReaderAt — io.ReaderAt поверх HTTP Range: zip читает каталог в конце файла и нужную запись.
// zip читает мелкими кусками — запросы идут блоками по 4 МБ с упреждением (~10 запросов на ffmpeg.exe).
type httpReaderAt struct {
	url   string
	total int64
	buf   []byte
	at    int64 // смещение buf в файле
}

const raBlock = 4 << 20

func (r *httpReaderAt) get(from, to int64) (*http.Response, error) {
	req, _ := http.NewRequest("GET", r.url, nil)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", from, to))
	resp, err := httpGet(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusPartialContent {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: нет поддержки Range (%s)", r.url, resp.Status)
	}
	return resp, nil
}

func (r *httpReaderAt) size() (int64, error) {
	resp, err := r.get(0, 0)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	_, total, _ := strings.Cut(resp.Header.Get("Content-Range"), "/") // bytes 0-0/114768076
	r.total, err = strconv.ParseInt(total, 10, 64)
	return r.total, err
}

func (r *httpReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.total {
		return 0, io.EOF
	}
	if off < r.at || off+int64(len(p)) > r.at+int64(len(r.buf)) { // нет в блоке — взять новый блок с off
		end := min(off+max(int64(len(p)), raBlock), r.total) - 1
		resp, err := r.get(off, end)
		if err != nil {
			return 0, err
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return 0, err
		}
		r.buf, r.at = b, off
	}
	n := copy(p, r.buf[off-r.at:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// httpGet — через прокси из окружения, а если он не отвечает — напрямую (мёртвый HTTPS_PROXY, как в agent.dial).
func httpGet(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil && strings.Contains(err.Error(), "proxyconnect") {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil
		resp, err = (&http.Client{Transport: t}).Do(req)
	}
	return resp, err
}
