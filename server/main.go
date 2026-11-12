// anypc-server — сигнализация + веб-клиент + лендинг. TLS через Let's Encrypt (autocert).
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"anypc/hub"
	"anypc/site"
	"anypc/ui"

	"golang.org/x/crypto/acme/autocert"
)

// newMux: хосты siteHosts → лендинг и /download/ (каталог dlDir); любой другой → веб-клиент и /ws.
func newMux(h http.Handler, siteHosts []string, dlDir string, turns, hubs []string) http.Handler {
	jsonList := func(l []string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(append([]string{}, l...))
		}
	}
	count := func(string, int) {}
	if c, ok := h.(interface{ Count(string, int) }); ok { // суточная сводка хаба (hub/stats.go)
		count = c.Count
	}
	page := func(key string, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				count(key, 1)
			}
			next.ServeHTTP(w, r)
		})
	}
	app, www := http.NewServeMux(), http.NewServeMux()
	for _, m := range []*http.ServeMux{app, www} {
		// TURN без учёток — клиент мерит до них пинг до подключения; хабы (wss://…/ws) — веб-клиент стучится во все,
		// лендинг берёт с них зеркала загрузок. CORS: окно программы (127.0.0.1) и страницы соседних узлов.
		m.HandleFunc("GET /turns", jsonList(turns))
		m.HandleFunc("GET /hubs", jsonList(hubs))
		if dlDir != "" { // загрузки на каждом узле: лендинг качает с ответившего первым
			fs := heavy(dlPool, http.StripPrefix("/download/", http.FileServer(http.Dir(dlDir))))
			m.Handle("/download/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				if name := path.Base(r.URL.Path); name != "/" && name != "." {
					if _, err := os.Stat(filepath.Join(dlDir, name)); err == nil { // только свои файлы: имена от сканеров не копятся
						count("dl/"+name, 1)
					}
				}
				if !strings.HasSuffix(r.URL.Path, "SHA256SUMS") {
					w.Header().Set("Content-Disposition", "attachment") // ссылка с чужого узла: атрибут download там не действует
				}
				fs.ServeHTTP(w, r)
			}))
		}
	}
	app.Handle("/ws", h)
	app.Handle("/", page("page_app", heavy(pagePool, http.FileServer(http.FS(ui.FS))))) // pake.wasm — 4 МБ, страница — 165 КБ
	www.Handle("/", page("page_www", heavy(pagePool, http.FileServer(http.FS(site.FS)))))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// срок записи прошлого тяжёлого ответа на этом keep-alive (heavy оставляет его на хвост) — снять
		http.NewResponseController(w).SetWriteDeadline(time.Time{})
		host := r.Host
		if hp, _, err := net.SplitHostPort(host); err == nil {
			host = hp
		}
		if slices.ContainsFunc(siteHosts, func(s string) bool { return strings.EqualFold(host, s) }) {
			secure(w, r, site.CSP)
			www.ServeHTTP(w, r)
			return
		}
		// Клиенту — только frame-ancestors: полная политика у него в <meta> (ui/index.html), а две полные
		// действовали бы обе, и расхождение хешей убило бы страницу; окно программы отдаёт ту же страницу без заголовка.
		secure(w, r, "frame-ancestors 'none'")
		app.ServeHTTP(w, r)
	})
}

// secure — заголовки безопасности на каждый ответ (обоим mux, включая /ws: в ответе 101 они безвредны).
// HSTS — только по TLS и без includeSubDomains/preload: с апекса он накрыл бы us.anypc.org:8080 (HTTP),
// а свой узел за обратным прокси (-addr без TLS) не должен навязывать HSTS домену оператора.
// max-age=86400 — первая неделя (сутки обратимы); год (31536000) — после недели без жалоб.
func secure(w http.ResponseWriter, r *http.Request, csp string) {
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer") // Origin у WebSocket и CORS от этого не обнуляется
	h.Set("Content-Security-Policy", csp)
	if r.TLS != nil {
		h.Set("Strict-Transport-Security", "max-age=86400")
	}
}

// version — из git-тега при сборке (build.sh).
var version = "dev"

func main() {
	domain := flag.String("domain", "", "домены клиента/сигнализации для TLS через запятую; пусто — HTTP на -addr (отладка)")
	siteHost := flag.String("site", "", "домены лендинга через запятую (anypc.org,www.anypc.org)")
	dl := flag.String("dl", "", "каталог файлов для /download/ на лендинге")
	addr := flag.String("addr", ":8080", "адрес HTTP без TLS")
	turn := flag.String("turn", "", "хосты STUN/TURN через запятую")
	hubs := flag.String("hubs", "", "все хабы сигнализации через запятую (wss://…/ws), для веб-клиента; пусто — только этот")
	certs := flag.String("certs", "certs", "каталог кэша сертификатов")
	maxConns := flag.Int("maxconns", 0, "потолок соединений сигнализации; сверх — 503; 0 — из памяти узла (memory.max cgroup или 60 % ОЗУ, по 300 КБ на соединение, не больше 5000), < 0 — ошибка")
	flag.Parse()
	if *maxConns < 0 { // иначе хаб отвечал бы 503 на всё
		log.Fatalf("-maxconns %d: нужен 0 (из памяти узла) или больше", *maxConns)
	}
	budget, from := memBudget(os.ReadFile)
	lim := plan(*maxConns, budget, os.Getenv("GOMEMLIMIT"))
	if lim.goLimit > 0 { // предел сборщика — запас до OOM; GOMEMLIMIT рантайм уже применил — он важнее
		debug.SetMemoryLimit(lim.goLimit)
	}

	h := &hub.Hub{TurnHosts: list(*turn), TurnSecret: os.Getenv("ANYPC_TURN_SECRET"), Keys: filepath.Join(filepath.Dir(*certs), "hosts.json"), MaxConns: lim.conns}
	mux := newMux(h, list(*siteHost), *dl, h.TurnHosts, list(*hubs))
	go h.StatsLoop(context.Background(), filepath.Dir(*certs), 10*time.Minute) // рядом с hosts.json: stats.jsonl — по строке на сутки
	port := *addr
	if *domain != "" {
		port = ":443"
	}
	l := listen(port, lim.tcp, TCPPerAddr)
	log.Print(memLine(budget, from, debug.SetMemoryLimit(-1), h.MaxConns, cap(l.sem))) // что действует на деле (TestMainWiring)
	if *domain == "" {
		log.Println("HTTP", *addr)
		log.Fatal(serve(*addr, mux).Serve(l))
	}
	hosts := list(*domain)
	hosts = append(hosts, list(*siteHost)...)
	m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(hosts...), Cache: autocert.DirCache(*certs)}
	go func() { log.Fatal(serve(":80", m.HTTPHandler(nil)).Serve(listen(":80", HTTPConns, HTTPPerAddr))) }()
	srv := serve(":443", mux)
	srv.TLSConfig = noH2(m.TLSConfig())
	log.Println("AnyPC server", version, "HTTPS", hosts)
	log.Fatal(srv.ServeTLS(l, "", ""))
}

// serve — сервер с таймаутами: без них простаивающие и медленные (slowloris) соединения копятся до OOM на VPS 1 ГБ.
// ReadHeaderTimeout и IdleTimeout WebSocket после Upgrade не трогают — его живость проверяет hub.Keepalive.
// ReadTimeout/WriteTimeout не ставить: дедлайн остаётся на захваченном соединении и рвёт WS через N секунд.
// IdleTimeout (ожидание следующего запроса keep-alive) захваченный WS не трогает: Hijack снимает сроки соединения
// (net/http, hijackLocked; TestIdleTimeoutKeepsWS). 10 с вместо 2 мин: простаивающее keep-alive занимает место
// под общим лимитом TCP (listen); когда запас выбран, новое соединение ждёт в очереди ядра не дольше ≈10 с
// (ReadHeaderTimeout — столько же для молчащих), а браузер просто откроет новое.
// MaxHeaderBytes 16 КБ (по умолчанию 1 МБ): наши запросы — сотни байт, а мегабайт заголовков на каждое
// из тысяч соединений — память VPS.
func serve(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}} // без HTTP/2 (noH2)
}

// noH2 — без HTTP/2 (Н1, Н2 повторной приёмки-7): потоки HTTP/2 не связаны с числом соединений (128 соединений ×
// 250 потоков GET /pake.wasm с адреса — OOM за 12–47 с), а срок записи потока не освобождает место, когда клиент
// не читает сокет. Веб-клиенту, загрузкам и WS он не нужен. ALPN autocert предлагает h2 — убрать (acme-tls/1 остаётся);
// TLSNextProto в serve пустой — сервер h2 не включает и сам.
func noH2(c *tls.Config) *tls.Config {
	c.NextProtos = slices.DeleteFunc(slices.Clone(c.NextProtos), func(p string) bool { return p == "h2" })
	return c
}

// list — "a, b,,c,a" → [a b c]: пустые и повторы отбрасываются (повторный запуск sed по флагам дал дубль, 2026-11-06).
func list(s string) []string {
	var r []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" && !slices.Contains(r, x) {
			r = append(r, x)
		}
	}
	return r
}
