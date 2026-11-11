package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"anypc/agent"
)

// Свой узел (SHARED-NODES.md, Э-1, режим A): хост регистрируется только на узле владельца,
// по галочке — ещё и на хабах AnyPC. Адрес узла — имя хоста[:порт]; программа сама дополняет до wss://…/ws.

var nodeRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(:[0-9]{1,5})?$`)

// normNode — «https://My.Example.com/» → «my.example.com»; "" — узлы AnyPC.
func normNode(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s, _, _ = strings.Cut(s, "/")
	if s != "" && !nodeRe.MatchString(s) {
		return "", errors.New("неверный адрес узла")
	}
	return s, nil
}

// nodeServer — значение config.Server для узла; public — оставаться и на хабах AnyPC.
func nodeServer(node string, public bool) string {
	if node == "" {
		return DefaultServer
	}
	s := "wss://" + node + "/ws"
	if public {
		s += "," + DefaultServer
	}
	return s
}

// nodeOf — обратно из config.Server: первый хаб не из DefaultServer; public — есть ли хабы AnyPC.
func nodeOf(server string) (node string, public bool) {
	def := strings.Split(DefaultServer, ",")
	for _, u := range strings.Split(server, ",") {
		u = strings.TrimSpace(u)
		if slices.Contains(def, u) {
			public = true
		} else if node == "" && u != "" {
			node = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(u, "wss://"), "ws://"), "/ws")
		}
	}
	return node, public || node == ""
}

// checkNode — по адресу отвечает узел AnyPC: GET base/hubs отдаёт JSON-список строк.
// Чужой /hubs в список хабов не берём (У10): нужен только сам ответ.
func checkNode(base string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"/hubs", nil)
	resp, err := httpGet(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var l []string
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&l) != nil {
		return errors.New("по этому адресу не узел AnyPC")
	}
	return nil
}

func (c *config) node() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return nodeOf(c.Server)
}

// setServer — сохранить новый список хабов; сам переход — restart.
func (c *config) setServer(s string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	c.Server = s
	return c.save()
}

// setViewOnly — галочка «Только показ экрана» из окна: при включении идущая сессия с полным доступом рвётся.
// dropAfter — правка записей удалась: сессия записи, которую удалили, сменили пароль или сузили права, рвётся.
func dropAfter(a *agent.Agent, err error) error {
	if err == nil {
		dropRevoked(a)
	}
	return err
}

// dropRevoked — agent.DropRevoked; переменная — тесты проверяют, что окно и опрос её зовут.
var dropRevoked = (*agent.Agent).DropRevoked

// pollConfig — опрос настроек раз в 2 с (Linux/Mac): правку ключом CLI при запущенной программе видно сразу —
// «Только показ экрана» рвёт сессию с полным доступом (REQ-F-25), --user / --user-del и смена режима — сессию
// отозванной записи, новый одноразовый код (--confirm on) — незавершённые входы со старым. last — код прошлого опроса.
func pollConfig(cfg *config, a *agent.Agent, last *string) {
	if cfg.viewNow() { // перечитывает файл целиком
		a.DisconnectFull()
	}
	dropRevoked(a)
	if c := cfg.code(); c != *last {
		*last = c
		if !cfg.ownCode(c) { // код сменил другой процесс: входы со старым кодом закрыть; свои смены закрыли их сами
			dropPending(a)
		}
	}
}

// dropPending — agent.DropPending (переменная — для тестов): код сменили ↻ или ключом CLI.
var dropPending = (*agent.Agent).DropPending

// newCode — ↻ в окне: новый код, незавершённые входы со старым закрыть.
func newCode(cfg *config, a *agent.Agent) (string, error) {
	c, err := cfg.newCode()
	if err == nil {
		dropPending(a)
	}
	return c, err
}

func setViewOnly(cfg *config, a *agent.Agent, on bool) error {
	err := cfg.setViewOnly(on)
	if err == nil && on {
		a.DisconnectFull()
	}
	return err
}

// runner — регистрация хоста с перезапуском при смене узла: старый Run останавливается целиком
// (a.Server читается только в Run), затем новый стартует с новым списком.
type runner struct {
	mu     sync.Mutex
	a      *agent.Agent
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

func (r *runner) start(server string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
		<-r.done
	}
	r.a.Server = server
	ctx, cancel := context.WithCancel(r.ctx)
	r.cancel, r.done = cancel, make(chan struct{})
	go func(done chan struct{}) { r.a.Run(ctx); close(done) }(r.done)
}

// wait — до остановки родительского ctx и последнего Run.
func (r *runner) wait() {
	<-r.ctx.Done()
	r.mu.Lock()
	defer r.mu.Unlock()
	<-r.done
}

// setNode — для окна: проверить узел, сохранить, перерегистрировать хост. Возвращает новый список хабов.
func setNode(cfg *config, r *runner, node string, public bool) (string, error) {
	s, err := applyNode(cfg, node, public)
	if err != nil {
		return "", err
	}
	r.start(s)
	return s, nil
}

// applyNode — проверить узел и записать в настройки (без перезапуска сигнализации: это делает setNode или новый запуск).
func applyNode(cfg *config, node string, public bool) (string, error) {
	n, err := normNode(node)
	if err != nil {
		return "", err
	}
	if n != "" {
		if err := checkNode("https://" + n); err != nil {
			return "", err
		}
	}
	s := nodeServer(n, public)
	if err := cfg.setServer(s); err != nil {
		return "", err
	}
	return s, nil
}

// audioInfo — предложение звука для окна хоста (PLAN.md): nil — ждать нечего.
func audioInfo(a *agent.Agent) map[string]any {
	if cid, sdp := a.AudioPending(); sdp != "" {
		return map[string]any{"cid": cid, "sdp": sdp, "ice": a.AudioICE()}
	}
	return nil
}
