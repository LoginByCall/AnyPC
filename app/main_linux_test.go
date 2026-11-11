package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anypc/agent"
	"anypc/pake"
	"anypc/totp"
)

func TestLocalAPI(t *testing.T) {
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	page, err := shimmed("wss://example/ws", "tok123")
	if err != nil || !strings.Contains(string(page), `const T = "tok123"`) || strings.Count(string(page), "<script>") < 2 {
		t.Fatalf("страница без привязок: %v", err)
	}
	h := handler("127.0.0.1:5000", "tok123", page, cfg, &agent.Agent{}, nil, func() map[string]any { return map[string]any{"id": cfg.ID} }, newFiles(t.TempDir()), nil)
	do := func(method, host, path, token string) (int, string) {
		r := httptest.NewRequest(method, path, strings.NewReader("[]"))
		r.Host = host
		if token != "" {
			r.Header.Set("X-Token", token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		b, _ := io.ReadAll(w.Result().Body)
		return w.Code, string(b)
	}
	for _, c := range []struct{ method, host, path, token string }{
		{"POST", "127.0.0.1:5000", "/api/hostInfo", ""},          // без токена
		{"POST", "127.0.0.1:5000", "/api/hostInfo", "wrong"},     // чужой токен
		{"POST", "evil.example:5000", "/api/hostInfo", "tok123"}, // DNS rebinding
		{"GET", "127.0.0.1:5000", "/api/hostInfo", "tok123"},     // не POST
		{"GET", "127.0.0.1:5000", "/", ""},                       // страница без ?t=
	} {
		if code, _ := do(c.method, c.host, c.path, c.token); code != 403 {
			t.Errorf("%+v → %d, ждали 403", c, code)
		}
	}
	if code, body := do("POST", "127.0.0.1:5000", "/api/hostInfo", "tok123"); code != 200 || !strings.Contains(body, cfg.ID) {
		t.Errorf("hostInfo: %d %s", code, body)
	}
	if code, body := do("POST", "127.0.0.1:5000", "/api/setPassword", "tok123"); code != 400 || !strings.Contains(body, "error") {
		t.Errorf("пустой пароль принят: %d %s", code, body)
	}
	if code, body := do("GET", "127.0.0.1:5000", "/?t=tok123", ""); code != 200 || !strings.Contains(body, "pakeRespond") {
		t.Errorf("страница: %d", code)
	}
	// правка записей из окна рвёт сессию отозванной записи (Д4): зовётся DropRevoked — и только при успехе
	var drops int
	dropRevoked = func(*agent.Agent) { drops++ }
	defer func() { dropRevoked = (*agent.Agent).DropRevoked }()
	call := func(name, args string) int {
		r := httptest.NewRequest("POST", "/api/"+name, strings.NewReader(args))
		r.Host = "127.0.0.1:5000"
		r.Header.Set("X-Token", "tok123")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for _, c := range []struct {
		name, args  string
		code, drops int
	}{
		{"setPassword", `["short"]`, 400, 0},
		{"setPassword", `["пароль-123"]`, 200, 1},
		{"userSet", `["ivan","пароль-ивана","full"]`, 200, 2},
		{"userSet", `["ivan","пароль-ивана","admin"]`, 400, 2},
		{"userDel", `["nobody"]`, 400, 2},
		{"userDel", `["ivan"]`, 200, 3},
	} {
		if code := call(c.name, c.args); code != c.code || drops != c.drops {
			t.Errorf("%s %s: %d, разрывов %d (ждали %d, %d)", c.name, c.args, code, drops, c.code, c.drops)
		}
	}
	pollConfig(cfg, &agent.Agent{}) // опрос настроек раз в 2 с — тоже (CLI при запущенной программе)
	if drops != 4 {
		t.Errorf("опрос настроек не зовёт DropRevoked: %d", drops)
	}
}

// TestOnceCode: браузер открывается одноразовым кодом (токена нет в аргументах, /proc/*/cmdline): первый заход —
// переадресация на страницу с токеном, повторный и чужой код — отказ.
func TestOnceCode(t *testing.T) {
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	once := &onceCode{code: "abc123"}
	h := handler("127.0.0.1:5000", "tok123", []byte("page"), cfg, &agent.Agent{}, nil, nil, newFiles(t.TempDir()), once)
	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "127.0.0.1:5000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := get("/?n=wrong"); w.Code != 403 {
		t.Errorf("чужой код: %d", w.Code)
	}
	if w := get("/?n=abc123"); w.Code != 303 || w.Header().Get("Location") != "/?t=tok123" {
		t.Errorf("первый заход: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := get("/?n=abc123"); w.Code != 403 {
		t.Errorf("повторный заход: %d", w.Code)
	}
}

// TestShimCSP: скрипт привязок (с токеном) разрешён в CSP страницы своим хэшем.
func TestShimCSP(t *testing.T) {
	page, err := shimmed("wss://example/ws", "tok123")
	if err != nil {
		t.Fatal(err)
	}
	s := string(page)
	i, j := strings.Index(s, "<script>"), strings.Index(s, "</script>")
	if !strings.Contains(s[i:j], "tok123") {
		t.Fatal("первый скрипт — не привязки")
	}
	sum := sha256.Sum256([]byte(s[i+len("<script>") : j]))
	if !strings.Contains(s, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Error("хэша скрипта привязок нет в CSP — браузер его не выполнит")
	}
}

// TestCLI — ключи командной строки: --version печатает версию из -ldflags, --id — ID из настроек, --help — список ключей;
// ни один не запускает хост.
func TestCLI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "anypc")
	if out, err := exec.Command("go", "build", "-ldflags=-X main.version=v9.9.9", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("сборка: %v\n%s", err, out)
	}
	home := t.TempDir() // свои ~/.config и ~/.cache: не трогать настройки разработчика
	run := func(arg string) string {
		c := exec.Command(bin, arg)
		c.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+home+"/.config", "XDG_CACHE_HOME="+home+"/.cache")
		out, _ := c.CombinedOutput()
		return string(out)
	}
	if out := run("--version"); out != "AnyPC v9.9.9\n" {
		t.Errorf("--version: %q", out)
	}
	if out := strings.TrimSpace(run("--id")); len(out) != 9 || strings.Trim(out, "0123456789") != "" {
		t.Errorf("--id: %q", out)
	}
	pw := func(in string) (string, error) {
		c := exec.Command(bin, "--password-stdin")
		c.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+home+"/.config", "XDG_CACHE_HOME="+home+"/.cache")
		c.Stdin = strings.NewReader(in)
		out, err := c.CombinedOutput()
		return string(out), err
	}
	if out, err := pw("short\n"); err == nil {
		t.Errorf("короткий пароль принят: %q", out)
	}
	if out, err := pw("secret123\n"); err != nil {
		t.Errorf("--password-stdin: %v %q", err, out)
	}
	cfg, err := loadConfig(filepath.Join(home, ".config", "AnyPC", "config.json"))
	if err != nil || !cfg.hasPass() || !bytes.Equal(cfg.Users[0].Hash, pake.KDF("secret123", cfg.Users[0].Salt)) {
		t.Errorf("пароль не записан: %v", err)
	}
	cli := func(args ...string) (string, error) {
		c := exec.Command(bin, args...)
		c.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+home+"/.config", "XDG_CACHE_HOME="+home+"/.cache")
		out, err := c.CombinedOutput()
		return string(out), err
	}
	{ // учётные записи (REQ-S-20): --user имя --password-stdin [--rights], список в --status, --user-del
		user := func(in string, args ...string) (string, error) {
			c := exec.Command(bin, append([]string{"--password-stdin"}, args...)...)
			c.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+home+"/.config", "XDG_CACHE_HOME="+home+"/.cache")
			c.Stdin = strings.NewReader(in)
			out, err := c.CombinedOutput()
			return string(out), err
		}
		if out, err := user("olga-pass1\n", "--user", "Olga", "--rights", "admin"); err == nil {
			t.Errorf("--rights admin принят: %q", out)
		}
		if out, err := user("olga-pass1\n", "--user", "a\tb"); err == nil {
			t.Errorf("имя с табуляцией принято: %q", out)
		}
		if out, err := user("olga-pass1\n", "--user", "Olga", "--rights", "view"); err != nil || !strings.Contains(out, "olga (view)") {
			t.Errorf("--user: %v %q", err, out)
		}
		c, _ := loadConfig(filepath.Join(home, ".config", "AnyPC", "config.json"))
		if s, h, v := c.secret("olga"); !v || !bytes.Equal(h, pake.KDF("olga-pass1", s)) || !c.hasPass() {
			t.Error("запись olga не записана или затёрла пароль по умолчанию")
		}
		if out, err := user("olga-pass2\n", "--user", "olga"); err != nil || !strings.Contains(out, "olga (view)") { // приёмка Д3
			t.Errorf("смена пароля без --rights: %v %q", err, out)
		}
		_, def, _ := c.secret("")
		if out, err := user("other-pass1\n", "--user", "  "); err == nil { // приёмка Д5
			t.Errorf("пустое имя принято: %q", out)
		}
		if c, _ := loadConfig(filepath.Join(home, ".config", "AnyPC", "config.json")); !bytes.Equal(func() []byte { _, h, _ := c.secret(""); return h }(), def) {
			t.Error("пустое --user сменило пароль по умолчанию")
		}
		if out, _ := cli("--status"); !strings.Contains(out, "  olga: view, TOTP: нет") {
			t.Errorf("--status без записи: %q", out)
		}
		if out, err := cli("--user-del", " "); err == nil {
			t.Errorf("--user-del без имени: %q", out)
		}
		if out, err := cli("--user-del", "OLGA"); err != nil {
			t.Errorf("--user-del: %v %q", err, out)
		}
		if out, _ := cli("--status"); !strings.Contains(out, "(кроме по умолчанию): нет") {
			t.Errorf("--status после удаления: %q", out)
		}
	}
	if out, err := cli("--confirm", "maybe"); err == nil {
		t.Errorf("--confirm maybe принят: %q", out)
	}
	if out, err := cli("--confirm", "off"); err == nil || !strings.Contains(out, "otpauth://totp/AnyPC:") || !strings.Contains(out, "▀") {
		t.Errorf("--confirm off без кода TOTP принят или нет QR: %v %q", err, out)
	}
	if c, _ := loadConfig(filepath.Join(home, ".config", "AnyPC", "config.json")); !c.confirm() || c.otpSet() {
		t.Error("без верного кода вход без подтверждения включился")
	}
	{ // TOTP в терминале: ключ из вывода → код в stdin
		c := exec.Command(bin, "--confirm", "off")
		c.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+home+"/.config", "XDG_CACHE_HOME="+home+"/.cache")
		in, _ := c.StdinPipe()
		outp, _ := c.StdoutPipe()
		c.Start()
		sc := bufio.NewScanner(outp)
		var out strings.Builder
		for sc.Scan() {
			out.WriteString(sc.Text() + "\n")
			if k, ok := strings.CutPrefix(sc.Text(), "Ключ: "); ok {
				code, _ := totp.Code(k, time.Now())
				io.WriteString(in, code+"\n")
			}
		}
		if err := c.Wait(); err != nil || !strings.Contains(out.String(), "второй фактор TOTP включён") {
			t.Errorf("--confirm off с кодом: %v %q", err, out.String())
		}
	}
	if out, err := cli("--view-only", "maybe"); err == nil {
		t.Errorf("--view-only maybe принят: %q", out)
	}
	if out, err := cli("--view-only", "on"); err != nil {
		t.Errorf("--view-only on: %v %q", err, out)
	}
	if out, err := cli("--node", "bad node!"); err == nil {
		t.Errorf("неверный узел принят: %q", out)
	}
	if out, err := cli("--node", "-"); err != nil {
		t.Errorf("--node -: %v %q", err, out)
	}
	cfg, _ = loadConfig(filepath.Join(home, ".config", "AnyPC", "config.json"))
	if cfg.confirm() || cfg.Server != DefaultServer {
		t.Errorf("настройки после ключей: confirm=%v server=%q", cfg.confirm(), cfg.Server)
	}
	if out, _ := cli("--status"); !strings.Contains(out, cfg.ID) || !strings.Contains(out, "Пароль задан: да") || !strings.Contains(out, "«Разрешить»: off") || !strings.Contains(out, "Второй фактор (TOTP): да") || !strings.Contains(out, "Только показ экрана: on") {
		t.Errorf("--status: %q", out)
	}
	if u := serviceUnit("/opt/my apps/AnyPC"); !strings.Contains(u, `ExecStart="/opt/my apps/AnyPC" --no-browser`) || !strings.Contains(u, "WantedBy=graphical-session.target") {
		t.Errorf("юнит: %q", u)
	}
	if u := serviceUnit(`/home/я/Загрузки/50%$x"y`); !strings.Contains(u, `ExecStart="/home/я/Загрузки/50%%$$x\"y" --no-browser`) {
		t.Errorf("юнит, экранирование: %q", u)
	}
	if out := run("--help"); !strings.Contains(out, "-no-browser") || !strings.Contains(out, "-version") || !strings.Contains(out, "v9.9.9") {
		t.Errorf("--help: %q", out)
	}
	// регрессия: ссылка окна с токеном (ключ к смене пароля) писалась в журнал — journald, anypc.log из тикетов
	cp := filepath.Join(home, ".config", "AnyPC", "config.json")
	var m map[string]any
	b, _ := os.ReadFile(cp)
	json.Unmarshal(b, &m)
	m["server"] = "ws://127.0.0.1:9/ws" // без сети: временный ID не регистрировать на настоящих хабах
	b, _ = json.Marshal(m)
	os.WriteFile(cp, b, 0o600)
	c := exec.Command(bin, "--no-browser")
	c.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+home+"/.config", "XDG_CACHE_HOME="+home+"/.cache")
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	urlFile := filepath.Join(home, ".cache", "AnyPC", "window.url")
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(urlFile); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.Process.Kill()
	c.Wait()
	u, err := os.ReadFile(urlFile)
	if st, _ := os.Stat(urlFile); err != nil || !strings.Contains(string(u), "/?t=") || st.Mode().Perm() != 0o600 {
		t.Errorf("window.url: %q %v", u, err)
	}
	logb, _ := os.ReadFile(filepath.Join(home, ".cache", "AnyPC", "anypc.log"))
	if !strings.Contains(string(logb), "window.url") || strings.Contains(string(logb), "?t=") || strings.Contains(stderr.String(), "?t=") {
		t.Errorf("токен окна в журнале:\n%s", logb)
	}
}
