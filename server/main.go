// anypc-server — сигнализация + веб-клиент + лендинг. TLS через Let's Encrypt (autocert).
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	maxConns := flag.Int("maxconns", hub.MaxConnsDefault, "потолок соединений сигнализации (≈55 КБ на WS по TLS); сверх — 503")
	flag.Parse()

	h := &hub.Hub{TurnHosts: list(*turn), TurnSecret: os.Getenv("ANYPC_TURN_SECRET"), Keys: filepath.Join(filepath.Dir(*certs), "hosts.json"), MaxConns: *maxConns}
	mux := newMux(h, list(*siteHost), *dl, h.TurnHosts, list(*hubs))
	if *domain == "" {
		log.Println("HTTP", *addr)
		log.Fatal(serve(*addr, mux).ListenAndServe())
	}
	hosts := list(*domain)
	hosts = append(hosts, list(*siteHost)...)
	m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(hosts...), Cache: autocert.DirCache(*certs)}
	go func() { log.Fatal(serve(":80", m.HTTPHandler(nil)).ListenAndServe()) }()
	srv := serve(":443", mux)
	srv.TLSConfig = m.TLSConfig()
	log.Println("AnyPC server", version, "HTTPS", hosts)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// serve — сервер с таймаутами: без них простаивающие и медленные (slowloris) соединения копятся до OOM на VPS 1 ГБ.
// WebSocket после Upgrade таймауты http.Server не трогают — его живость проверяет hub.Keepalive.
func serve(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
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
