// Package ui — интерфейс AnyPC (один HTML): веб-клиент на сервере и окно программы AnyPC.exe.
// pake.wasm и wasm_exec.js генерирует build.sh (CPace для браузера).
package ui

import "embed"

//go:embed index.html embed.js pake.wasm wasm_exec.js
var FS embed.FS
