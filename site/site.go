// Package site — промо-лендинг www (один HTML, без внешних ресурсов: часть CDN недоступна из КНР).
package site

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"strings"
)

//go:embed index.html privacy.html
var FS embed.FS

// CSP — политика лендинга (отдаётся заголовком). Единственный встроенный скрипт разрешён по sha256,
// посчитанному из встроенного index.html при старте: скрипт несёт переводы и меняется с каждой правкой текстов,
// хеш, вписанный руками, устаревал бы. connect-src https: — зеркала загрузок на соседних хабах (wss → https).
var CSP = "default-src 'none'; script-src " + ScriptHash() + "; style-src 'unsafe-inline'; img-src 'self' data:; " +
	"connect-src 'self' https:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// ScriptHash — источник CSP для встроенного <script> index.html: 'sha256-…'.
func ScriptHash() string {
	b, _ := FS.ReadFile("index.html")
	s := string(b)
	i, j := strings.Index(s, "<script>"), strings.Index(s, "</script>")
	if i < 0 || j < i {
		return "'none'"
	}
	sum := sha256.Sum256([]byte(s[i+len("<script>") : j]))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}
