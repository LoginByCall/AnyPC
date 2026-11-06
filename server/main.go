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
			www.ServeHTTP(w, r)
			return
		}
		app.ServeHTTP(w, r)
	})
}

func main() {
	domain := flag.String("domain", "", "домены клиента/сигнализации для TLS через запятую; пусто — HTTP на -addr (отладка)")
	siteHost := flag.String("site", "", "домены лендинга через запятую (anypc.org,www.anypc.org)")
	dl := flag.String("dl", "", "каталог файлов для /download/ на лендинге")
	addr := flag.String("addr", ":8080", "адрес HTTP без TLS")
	turn := flag.String("turn", "", "хосты STUN/TURN через запятую")
	hubs := flag.String("hubs", "", "все хабы сигнализации через запятую (wss://…/ws), для веб-клиента; пусто — только этот")
	certs := flag.String("certs", "certs", "каталог кэша сертификатов")
	flag.Parse()

	h := &hub.Hub{TurnHosts: list(*turn), TurnSecret: os.Getenv("ANYPC_TURN_SECRET"), Keys: filepath.Join(filepath.Dir(*certs), "hosts.json")}
	mux := newMux(h, list(*siteHost), *dl, h.TurnHosts, list(*hubs))
	if *domain == "" {
		log.Println("HTTP", *addr)
		log.Fatal(http.ListenAndServe(*addr, mux))
	}
	hosts := list(*domain)
	hosts = append(hosts, list(*siteHost)...)
	m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(hosts...), Cache: autocert.DirCache(*certs)}
	go func() { log.Fatal(http.ListenAndServe(":80", m.HTTPHandler(nil))) }()
	srv := &http.Server{Addr: ":443", Handler: mux, TLSConfig: m.TLSConfig(), ReadHeaderTimeout: 10 * time.Second}
	log.Println("HTTPS", hosts)
	log.Fatal(srv.ListenAndServeTLS("", ""))
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
