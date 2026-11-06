// anypc-server — сигнализация + веб-клиент + лендинг. TLS через Let's Encrypt (autocert).
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"anypc/hub"
	"anypc/site"
	"anypc/ui"

	"golang.org/x/crypto/acme/autocert"
)

// newMux: хост siteHost → лендинг и /download/ (каталог dlDir); любой другой → веб-клиент и /ws.
func newMux(h http.Handler, siteHost, dlDir string) http.Handler {
	app := http.NewServeMux()
	app.Handle("/ws", h)
	app.Handle("/", http.FileServer(http.FS(ui.FS)))
	www := http.NewServeMux()
	www.Handle("/", http.FileServer(http.FS(site.FS)))
	if dlDir != "" {
		www.Handle("/download/", http.StripPrefix("/download/", http.FileServer(http.Dir(dlDir))))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if hp, _, err := net.SplitHostPort(host); err == nil {
			host = hp
		}
		if siteHost != "" && strings.EqualFold(host, siteHost) {
			www.ServeHTTP(w, r)
			return
		}
		app.ServeHTTP(w, r)
	})
}

func main() {
	domain := flag.String("domain", "", "домены клиента/сигнализации для TLS через запятую; пусто — HTTP на -addr (отладка)")
	siteHost := flag.String("site", "", "домен лендинга (www…)")
	dl := flag.String("dl", "", "каталог файлов для /download/ на лендинге")
	addr := flag.String("addr", ":8080", "адрес HTTP без TLS")
	turn := flag.String("turn", "", "хосты STUN/TURN через запятую, по порядку предпочтения")
	certs := flag.String("certs", "certs", "каталог кэша сертификатов")
	flag.Parse()

	h := &hub.Hub{TurnHosts: list(*turn), TurnSecret: os.Getenv("ANYPC_TURN_SECRET"), Keys: filepath.Join(filepath.Dir(*certs), "hosts.json")}
	mux := newMux(h, *siteHost, *dl)
	if *domain == "" {
		log.Println("HTTP", *addr)
		log.Fatal(http.ListenAndServe(*addr, mux))
	}
	hosts := list(*domain)
	if *siteHost != "" {
		hosts = append(hosts, *siteHost)
	}
	m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(hosts...), Cache: autocert.DirCache(*certs)}
	go func() { log.Fatal(http.ListenAndServe(":80", m.HTTPHandler(nil))) }()
	srv := &http.Server{Addr: ":443", Handler: mux, TLSConfig: m.TLSConfig(), ReadHeaderTimeout: 10 * time.Second}
	log.Println("HTTPS", hosts)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// list — "a, b,,c" → [a b c].
func list(s string) []string {
	var r []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			r = append(r, x)
		}
	}
	return r
}
