// anypc-server — сигнализация + веб-клиент + лендинг. TLS через Let's Encrypt (autocert).
package main

import (
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
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
	app, www := http.NewServeMux(), http.NewServeMux()
	for _, m := range []*http.ServeMux{app, www} {
		// TURN без учёток — клиент мерит до них пинг до подключения; хабы (wss://…/ws) — веб-клиент стучится во все,
		// лендинг берёт с них зеркала загрузок. CORS: окно программы (127.0.0.1) и страницы соседних узлов.
		m.HandleFunc("GET /turns", jsonList(turns))
		m.HandleFunc("GET /hubs", jsonList(hubs))
		if dlDir != "" { // загрузки на каждом узле: лендинг качает с ответившего первым
			fs := http.StripPrefix("/download/", http.FileServer(http.Dir(dlDir)))
			m.Handle("/download/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				if !strings.HasSuffix(r.URL.Path, "SHA256SUMS") {
					w.Header().Set("Content-Disposition", "attachment") // ссылка с чужого узла: атрибут download там не действует
				}
				fs.ServeHTTP(w, r)
			}))
		}
	}
	app.Handle("/ws", h)
	app.Handle("/", http.FileServer(http.FS(ui.FS)))
	www.Handle("/", http.FileServer(http.FS(site.FS)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	conns := cmp.Or(*maxConns, hub.ConnsFor(budget)) // явный -maxconns важнее
	if os.Getenv("GOMEMLIMIT") == "" && budget > 0 { // предел сборщика — запас до OOM; GOMEMLIMIT рантайм уже применил — он важнее
		debug.SetMemoryLimit(budget * 8 / 10)
	}
	log.Print(memLine(budget, from, debug.SetMemoryLimit(-1), conns))

	h := &hub.Hub{TurnHosts: list(*turn), TurnSecret: os.Getenv("ANYPC_TURN_SECRET"), Keys: filepath.Join(filepath.Dir(*certs), "hosts.json"), MaxConns: conns}
	mux := newMux(h, list(*siteHost), *dl, h.TurnHosts, list(*hubs))
	if *domain == "" {
		log.Println("HTTP", *addr)
		log.Fatal(serve(*addr, mux).Serve(listen(*addr, tcpLimit(conns))))
	}
	hosts := list(*domain)
	hosts = append(hosts, list(*siteHost)...)
	m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(hosts...), Cache: autocert.DirCache(*certs)}
	go func() { log.Fatal(serve(":80", m.HTTPHandler(nil)).Serve(listen(":80", HTTPConns))) }()
	srv := serve(":443", mux)
	srv.TLSConfig = m.TLSConfig()
	log.Println("AnyPC server", version, "HTTPS", hosts)
	log.Fatal(srv.ServeTLS(listen(":443", tcpLimit(conns)), "", ""))
}

// HTTPConns — TCP-соединений сверх потолка WS (Д1″ приёмки-6, D5 приёмки-1): страница, сайт, загрузки, /turns, /hubs
// и простаивающие keep-alive. Их не видят ни MaxConns, ни лимиты «на адрес» (≈20 КБ каждое: 3500 штук сверх 5000 WS
// убивали хаб за 5 с), поэтому всё TCP на порту — под общим лимитом; сверх него новое соединение ждёт в очереди
// ядра, пока не освободится место. На :80 (вызов ACME и редирект) — только он.
const HTTPConns = 256

// tcpLimit — всех TCP-соединений на порту сигнализации: WS плюс 10 % (не меньше HTTPConns) на HTTP.
func tcpLimit(conns int) int { return conns + max(conns/10, HTTPConns) }

// RcvBuf — приёмный буфер ядра у каждого принятого соединения (Д1″ (в) приёмки-6). По умолчанию ядро растит его до
// мегабайт на сокет, а когда хаб под атакой не успевает читать (медленное ядро, поток хостов к клиентам), буферы
// сокетов — вне предела Go — съедали 170–215 МиБ из 574. 32 КБ (ядро удваивает): сигнализации и загрузкам на узел
// хватает (входящий поток — только сообщения ≤ 64 КБ и запросы), отправитель просто ждёт окна.
const RcvBuf = 32 << 10

// limitListener — не больше cap(sem) соединений одновременно: n+1-е ждёт в Accept (в очереди ядра), как
// netutil.LimitListener. Свой, а не netutil: его обёртка соединения прячет *net.TCPConn, а hub ставит SndBuf
// захваченному WS через SetWriteBuffer — здесь он виден (limConn встраивает *net.TCPConn).
type limitListener struct {
	*net.TCPListener
	sem chan struct{}
}

func (l limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.AcceptTCP()
	if err != nil {
		<-l.sem
		return nil, err
	}
	c.SetReadBuffer(RcvBuf)
	return &limConn{TCPConn: c, release: func() { <-l.sem }}, nil
}

type limConn struct {
	*net.TCPConn
	once    sync.Once
	release func()
}

func (c *limConn) Close() error {
	err := c.TCPConn.Close()
	c.once.Do(c.release)
	return err
}

// listen — TCP на addr не больше n соединений одновременно, RcvBuf у каждого.
func listen(addr string, n int) net.Listener {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	return limitListener{l.(*net.TCPListener), make(chan struct{}, n)}
}

// memBudget — память узла для хаба: memory.max своей cgroup и её предков (наименьший; MemoryMax unit-файла —
// у прода 60 % ОЗУ), иначе 60 % MemTotal; 0 — не узнать (тогда потолок — MinConns). from — откуда взято.
func memBudget(read func(string) ([]byte, error)) (budget int64, from string) {
	if b, err := read("/proc/self/cgroup"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			p, ok := strings.CutPrefix(l, "0::")
			if !ok {
				continue
			}
			for dir := path.Clean(p); ; dir = path.Dir(dir) {
				f := path.Join("/sys/fs/cgroup", dir, "memory.max")
				if v, err := read(f); err == nil {
					if n, err := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64); err == nil && n > 0 && (budget == 0 || n < budget) {
						budget, from = n, f
					}
				}
				if dir == "/" {
					break
				}
			}
		}
	}
	if budget > 0 {
		return budget, from
	}
	if b, err := read("/proc/meminfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "MemTotal:" {
				if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					return kb << 10 * 6 / 10, "60 % MemTotal"
				}
			}
		}
	}
	return 0, "не определена"
}

// memLine — строка журнала при старте: откуда потолки.
func memLine(budget int64, from string, goLimit int64, conns int) string {
	return fmt.Sprintf("память: бюджет %s (%s), предел Go %s; соединений сигнализации %d, TCP %d", mib(budget), from, mib(goLimit), conns, tcpLimit(conns))
}

// mib — байты для журнала; без предела (math.MaxInt64 от SetMemoryLimit) и 0 — словами.
func mib(n int64) string {
	switch {
	case n <= 0:
		return "неизвестен"
	case n >= 1<<62:
		return "нет"
	}
	return strconv.FormatInt(n>>20, 10) + " МиБ"
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
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10}
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
