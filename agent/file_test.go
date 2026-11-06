package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

func TestSafeName(t *testing.T) {
	for in, want := range map[string]string{
		"отчёт.pdf":           "отчёт.pdf",
		`..\..\Windows\x.dll`: "x.dll",
		"../evil:name?.bin":   "evil_name_.bin",
		"con.txt":             "_con.txt",
		"name. . ":            "name",
		"":                    "_",
		"a\x01b":              "a_b",
	} {
		if got := safeName(in); got != want {
			t.Errorf("safeName(%q) = %q, ждали %q", in, got, want)
		}
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), nil, 0o644)
	os.WriteFile(filepath.Join(dir, "a (1).txt"), nil, 0o644)
	if got := filepath.Base(freePath(dir, "a.txt")); got != "a (2).txt" {
		t.Errorf("freePath: %s", got)
	}
}

// pair — два соединённых WebRTC-узла в одном процессе (без сигнализации).
func pair(t *testing.T) (client, host *webrtc.PeerConnection) {
	t.Helper()
	client, _ = webrtc.NewPeerConnection(webrtc.Configuration{})
	host, _ = webrtc.NewPeerConnection(webrtc.Configuration{})
	t.Cleanup(func() { client.Close(); host.Close() })
	client.CreateDataChannel("init", nil)
	offer, _ := client.CreateOffer(nil)
	g := webrtc.GatheringCompletePromise(client)
	client.SetLocalDescription(offer)
	<-g
	host.SetRemoteDescription(*client.LocalDescription())
	ans, _ := host.CreateAnswer(nil)
	g = webrtc.GatheringCompletePromise(host)
	host.SetLocalDescription(ans)
	<-g
	client.SetRemoteDescription(*host.LocalDescription())
	return client, host
}

func randFile(t *testing.T, n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// upload — клиент шлёт файл так же, как ui/index.html; cancelAt > 0 — закрыть канал после стольких байт.
func upload(t *testing.T, pc *webrtc.PeerConnection, name string, data []byte, cancelAt int) fileMsg {
	dc, _ := pc.CreateDataChannel("file", nil)
	res := make(chan fileMsg, 1)
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		var fm fileMsg
		json.Unmarshal(m.Data, &fm)
		res <- fm
	})
	dc.OnOpen(func() {
		sendJSON(dc, fileMsg{T: "meta", Name: name, Size: int64(len(data))})
		for off := 0; off < len(data); off += fileChunk {
			if cancelAt > 0 && off >= cancelAt {
				dc.Close()
				return
			}
			for dc.BufferedAmount() > fileHigh {
				time.Sleep(time.Millisecond)
			}
			dc.Send(data[off:min(off+fileChunk, len(data))])
		}
		sendJSON(dc, fileMsg{T: "end"})
	})
	if cancelAt > 0 {
		return fileMsg{}
	}
	select {
	case r := <-res:
		return r
	case <-time.After(20 * time.Second):
		t.Fatal("нет ответа хоста")
	}
	return fileMsg{}
}

func TestFileUpload(t *testing.T) {
	client, host := pair(t)
	dir := t.TempDir()
	a := &Agent{FileDir: dir}
	host.OnDataChannel(func(dc *webrtc.DataChannel) {
		if dc.Label() == "file" {
			a.receiveFile(dc)
		}
	})
	data := randFile(t, 3<<20)
	r := upload(t, client, "../evil:name.bin", data, 0)
	sum := sha256.Sum256(data)
	got, err := os.ReadFile(filepath.Join(dir, "evil_name.bin")) // имя очищено, из папки не вышли
	if r.T != "done" || err != nil || !bytes.Equal(got, data) {
		t.Fatalf("приём: %+v %v", r, err)
	}
	if r.SHA256 != hexs(sum[:]) {
		t.Fatal("SHA-256 в ответе не совпадает")
	}

	// отмена: недокачанный файл удаляется
	upload(t, client, "big.bin", randFile(t, 2<<20), 256<<10)
	for i := 0; i < 50; i++ {
		ents, _ := os.ReadDir(dir)
		if len(ents) == 1 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	ents, _ := os.ReadDir(dir)
	t.Fatalf("после отмены остались файлы: %v", ents)
}

func TestFileDownload(t *testing.T) {
	client, host := pair(t)
	data := randFile(t, 3<<20)
	src := filepath.Join(t.TempDir(), "с хоста.bin")
	os.WriteFile(src, data, 0o644)
	var got bytes.Buffer
	name := make(chan string, 1)
	recv := make(chan []byte, 1)
	client.OnDataChannel(func(dc *webrtc.DataChannel) { // как приёмник в ui/index.html
		dc.OnMessage(func(m webrtc.DataChannelMessage) {
			if !m.IsString {
				got.Write(m.Data)
				return
			}
			var fm fileMsg
			json.Unmarshal(m.Data, &fm)
			if fm.T == "meta" {
				name <- fm.Name
			}
			if fm.T == "end" {
				recv <- got.Bytes()
				sendJSON(dc, fileMsg{T: "done"})
				dc.Close()
			}
		})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := sendFile(ctx, host, src); err != nil {
		t.Fatal(err)
	}
	if <-name != "с хоста.bin" || !bytes.Equal(<-recv, data) {
		t.Fatal("файл с хоста искажён")
	}
}

func hexs(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, h[c>>4], h[c&15])
	}
	return string(out)
}
