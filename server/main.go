// anypc-server — сигнализация + веб-клиент + лендинг. TLS через Let's Encrypt (autocert).
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
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
	domain := flag.String("domain", "", "домен клиента/сигнализации для TLS; пусто — HTTP на -addr (отладка)")
	siteHost := flag.String("site", "", "домен лендинга (www…)")
	dl := flag.String("dl", "", "каталог файлов для /download/ на лендинге")
	addr := flag.String("addr", ":8080", "адрес HTTP без TLS")
	turn := flag.String("turn", "", "хост STUN/TURN")
	certs := flag.String("certs", "certs", "каталог кэша сертификатов")
	flag.Parse()

	mux := newMux(&hub.Hub{TurnHost: *turn, TurnSecret: os.Getenv("ANYPC_TURN_SECRET")}, *siteHost, *dl)
	if *domain == "" {
		log.Println("HTTP", *addr)
		log.Fatal(http.ListenAndServe(*addr, mux))
	}
	hosts := []string{*domain}
	if *siteHost != "" {
		hosts = append(hosts, *siteHost)
	}
	m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(hosts...), Cache: autocert.DirCache(*certs)}
	go func() { log.Fatal(http.ListenAndServe(":80", m.HTTPHandler(nil))) }()
	srv := &http.Server{Addr: ":443", Handler: mux, TLSConfig: m.TLSConfig(), ReadHeaderTimeout: 10 * time.Second}
	log.Println("HTTPS", hosts)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
