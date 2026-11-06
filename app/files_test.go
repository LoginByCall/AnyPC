package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestFilesBinding(t *testing.T) {
	dir := t.TempDir()
	f := newFiles(dir)
	b := base64.StdEncoding.EncodeToString
	id := "0123456789abcdef0123456789abcdef"
	r, err := f.Open("отчёт.txt", 6, id)
	if err != nil || r["offset"].(int64) != 0 {
		t.Fatal(r, err)
	}
	h := r["handle"].(int)
	f.Write(h, b([]byte("abc")))
	f.Abort(h, true) // обрыв
	r, _ = f.Open("отчёт.txt", 6, id)
	if r["offset"].(int64) != 3 {
		t.Fatalf("докачка с %v", r["offset"])
	}
	h = r["handle"].(int)
	if f.Write(h, "не base64!") == nil {
		t.Fatal("мусор принят")
	}
	f.Write(h, b([]byte("def")))
	res, err := f.Finish(h)
	if got, _ := os.ReadFile(filepath.Join(dir, "отчёт.txt")); err != nil || string(got) != "abcdef" || res["name"] != "отчёт.txt" {
		t.Fatalf("%q %v %v", got, res, err)
	}
	if f.Write(h, b([]byte("x"))) == nil {
		t.Fatal("запись после Finish")
	}
}
