package pake

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestWASM — браузерный путь веб-клиента: pake.wasm (в Node) отвечает хосту на Go.
func TestWASM(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("нет node")
	}
	dir := t.TempDir()
	wasm := filepath.Join(dir, "pake.wasm")
	b := exec.Command("go", "build", "-o", wasm, "../wasm")
	b.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if out, err := b.CombinedOutput(); err != nil {
		t.Fatalf("сборка wasm: %v\n%s", err, out)
	}
	root, _ := exec.Command("go", "env", "GOROOT").Output()
	execJS := filepath.Join(string(root[:len(root)-1]), "lib", "wasm", "wasm_exec.js")

	salt := []byte("0123456789abcdef")
	lsdp, rsdp := "a=fingerprint:sha-256 AA:BB\r\n", "a=fingerprint:sha-256 CC:DD\r\n"
	msgA, st, err := HostStart(KDF("пароль-123", salt), "123456789", Fingerprint(lsdp), Fingerprint(rsdp))
	if err != nil {
		t.Fatal(err)
	}
	script := `require(process.argv[2]);
const go = new Go();
WebAssembly.instantiate(require('fs').readFileSync(process.argv[3]), go.importObject).then(r => {
  go.run(r.instance);
  return pakeRespond(...process.argv.slice(4));
}).then(x => { console.log(JSON.stringify(x)); process.exit(0); }, e => { console.error(e); process.exit(1); });`
	js := filepath.Join(dir, "t.js")
	os.WriteFile(js, []byte(script), 0o600)
	b64 := base64.StdEncoding.EncodeToString
	out, err := exec.Command("node", js, execJS, wasm, "пароль-123", b64(salt), b64(msgA), "123456789", lsdp, rsdp).Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	var r struct{ Msg, Conf, Expect []byte }
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	hConf, err := HostFinish(st, r.Msg, r.Conf)
	if err != nil || b64(hConf) != b64(r.Expect) {
		t.Fatalf("хост не принял ответ WASM: %v", err)
	}
}
