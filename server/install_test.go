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

// TestInstallVerify — П1: install.sh берёт anypc-server только с верной подписью SHA256SUMS ключом выпуска
// и не ниже MIN_VERSION; лежащий рядом файл — только по ANYPC_LOCAL=1.
func TestInstallVerify(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("нет openssl")
	}
	script, _ := filepath.Abs("../deploy/setup.sh")
	bin := []byte("anypc-server от зеркала")
	sums := func(ver string) []byte {
		return []byte(fmt.Sprintf("%x  anypc-server\n%x  VERSION\n", sha256.Sum256(bin), sha256.Sum256([]byte(ver+"\n"))))
	}
	// run — install.sh так, как его запускают с лендинга (`curl … | sh -s домен`), в каталоге cwd, с зеркалом из файлов
	run := func(cwd, ver string, sig []byte) error {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "anypc-server"), bin, 0o644)
		os.WriteFile(filepath.Join(dir, "VERSION"), []byte(ver+"\n"), 0o644)
		os.WriteFile(filepath.Join(dir, "SHA256SUMS"), sums(ver), 0o644)
		if sig != nil {
			os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), sig, 0o644)
		}
		srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
		defer srv.Close()
		f, _ := os.Open(script)
		defer f.Close()
		cmd := exec.Command("sh", "-s", "example.com")
		cmd.Stdin, cmd.Dir = f, cwd
		cmd.Env = append(os.Environ(), "ANYPC_DL="+srv.URL, "ANYPC_DL_ONLY=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("install.sh: %s", out)
		}
		return err
	}
	if run(t.TempDir(), "v9.9.9", nil) == nil {
		t.Error("принят SHA256SUMS без подписи")
	}
	evil := filepath.Join(t.TempDir(), "evil.pem")
	exec.Command("openssl", "genpkey", "-algorithm", "ed25519", "-out", evil).Run()
	if sig, _ := sign(evil, sums("v9.9.9")); run(t.TempDir(), "v9.9.9", sig) == nil {
		t.Error("принята подпись чужим ключом")
	}
	planted := t.TempDir() // «рядом» при curl | sh — текущий каталог
	os.WriteFile(filepath.Join(planted, "anypc-server"), []byte("подброшен"), 0o755)
	if run(planted, "v9.9.9", nil) == nil {
		t.Error("взят лежащий рядом файл без ANYPC_LOCAL и без подписи")
	}
	key := os.ExpandEnv("$HOME/.config/anypc/release-ed25519.pem")
	if _, err := os.Stat(key); err != nil {
		t.Log("нет ключа выпуска — случаи с верной подписью пропущены")
		return
	}
	if sig, _ := sign(key, sums("v0.1.0")); run(t.TempDir(), "v0.1.0", sig) == nil {
		t.Error("принят подписанный, но старый выпуск (откат версии)")
	}
	sig, err := sign(key, sums("v9.9.9"))
	if err != nil {
		t.Fatal(err)
	}
	if err := run(t.TempDir(), "v9.9.9", sig); err != nil {
		t.Errorf("подпись ключом выпуска не принята (открытый ключ в setup.sh не от него?): %v", err)
	}
}

func sign(key string, data []byte) ([]byte, error) {
	f := filepath.Join(os.TempDir(), "anypc-sums")
	os.WriteFile(f, data, 0o600)
	defer os.Remove(f)
	return exec.Command("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", f).Output()
}
