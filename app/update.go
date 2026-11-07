package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Проверка обновлений: build.sh кладёт файл VERSION рядом с дистрибутивом, publish.sh выкладывает его на хабы.
// Только подсказка: ссылка «обновить» всегда ведёт на www.anypc.org, а не на узел, поэтому подменённый VERSION
// даёт лишь лишнее «обновите». ponytail: без автозамены exe — для неё нужна подпись релиза (SHARED-NODES.md, П1).
const updateSite = "https://www.anypc.org/#get"

// updateURLs — VERSION на наших хабах (не на «своём сервере» пользователя): http(s)-адреса из DefaultServer.
var updateURLs = func() (l []string) {
	for _, u := range strings.Split(DefaultServer, ",") {
		l = append(l, strings.Replace(strings.TrimSuffix(u, "/ws"), "wss://", "https://", 1)+"/download/VERSION")
	}
	return l
}()

var releaseRe = regexp.MustCompile(`^v\d+\.\d+\.\d+$`) // только выпуски с тегом: v0.1.2, не v0.1.1-3-gabc

func semver(v string) (n [3]int, ok bool) {
	_, err := fmt.Sscanf(v, "v%d.%d.%d", &n[0], &n[1], &n[2])
	return n, err == nil
}

// newer — remote (выпуск) новее local; local может быть сборкой между тегами (v0.1.1-2-g…) или "dev" — тогда false.
func newer(remote, local string) bool {
	r, ok1 := semver(remote)
	l, ok2 := semver(local)
	return releaseRe.MatchString(remote) && ok1 && ok2 && slices.Compare(r[:], l[:]) > 0
}

// latestVersion — версия с первого ответившего хаба ("" — никто не ответил внятно).
func latestVersion() string {
	for _, u := range updateURLs {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		resp, err := httpGet(req)
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
			resp.Body.Close()
			if v := strings.TrimSpace(string(b)); resp.StatusCode == http.StatusOK && releaseRe.MatchString(v) {
				cancel()
				return v
			}
		}
		cancel()
	}
	return ""
}

// watchUpdates — при запуске и раз в 12 ч (хост работает неделями); found(v) — есть выпуск новее этой программы.
func watchUpdates(found func(string)) {
	for {
		if v := latestVersion(); newer(v, version) {
			log.Printf("доступна версия %s (у меня %s)", v, version)
			found(v)
		}
		time.Sleep(12 * time.Hour)
	}
}
