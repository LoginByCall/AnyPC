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
	c.Server = s
	return c.save()
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
	r.start(s)
	return s, nil
}
