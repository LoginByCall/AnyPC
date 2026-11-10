// Package site — промо-лендинг www (один HTML, без внешних ресурсов: часть CDN недоступна из КНР).
package site

import "embed"

//go:embed index.html privacy.html
var FS embed.FS
