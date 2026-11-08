package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestInstallVerify — П1: install.sh берёт anypc-server только с верной подписью SHA256SUMS ключом выпуска.
// Подменённое зеркало (своя сумма, чужая или нет подписи) — отказ; с ключом владельца — принимает.
func TestInstallVerify(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("нет openssl")
	}
	bin := []byte("anypc-server от зеркала")
	sums := []byte(fmt.Sprintf("%x  anypc-server\n", sha256.Sum256(bin)))
	run := func(sig []byte) error {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "anypc-server"), bin, 0o644)
		os.WriteFile(filepath.Join(dir, "SHA256SUMS"), sums, 0o644)
		if sig != nil {
			os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), sig, 0o644)
		}
		srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
		defer srv.Close()
		script, _ := filepath.Abs("../deploy/setup.sh")
		cmd := exec.Command("sh", script, "example.com")
		cmd.Env = append(os.Environ(), "ANYPC_DL="+srv.URL, "ANYPC_DL_ONLY=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("install.sh: %s", out)
		}
		return err
	}
	if run(nil) == nil {
		t.Error("принят SHA256SUMS без подписи")
	}
	// отказ должен быть из-за подписи, а не раньше: тот же скрипт с верной суммой без ключа выпуска у теста
	// проходит до проверки — это видно в журнале («не прошли проверку»)
	evil := filepath.Join(t.TempDir(), "evil.pem")
	exec.Command("openssl", "genpkey", "-algorithm", "ed25519", "-out", evil).Run()
	if sig, _ := sign(evil, sums); run(sig) == nil {
		t.Error("принята подпись чужим ключом")
	}
	key := os.ExpandEnv("$HOME/.config/anypc/release-ed25519.pem")
	if _, err := os.Stat(key); err != nil {
		t.Log("нет ключа выпуска — положительный случай пропущен")
		return
	}
	sig, err := sign(key, sums)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(sig); err != nil {
		t.Errorf("подпись ключом выпуска не принята (открытый ключ в setup.sh не от него?): %v", err)
	}
}

func sign(key string, data []byte) ([]byte, error) {
	f := filepath.Join(os.TempDir(), "anypc-sums")
	os.WriteFile(f, data, 0o600)
	defer os.Remove(f)
	return exec.Command("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", f).Output()
}
