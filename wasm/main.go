//go:build js && wasm

// pake.wasm — CPace для веб-клиента в браузере (тот же код, что в AnyPC.exe).
// Экспортирует window.pakeRespond(pass, salt, msgA, hostID, localSDP, remoteSDP) → Promise<{msg, conf, expect}>.
package main

import (
	"syscall/js"

	"anypc/pake"
)

func main() {
	js.Global().Set("pakeRespond", js.FuncOf(func(_ js.Value, a []js.Value) any {
		args := make([]string, 6)
		for i := range args {
			if i < len(a) {
				args[i] = a[i].String()
			}
		}
		return js.Global().Get("Promise").New(js.FuncOf(func(_ js.Value, pr []js.Value) any {
			go func() { // Argon2id 64 МБ — не блокировать вызов
				r, err := pake.ClientRespondB64(args[0], args[1], args[2], args[3], args[4], args[5])
				if err != nil {
					pr[1].Invoke(js.Global().Get("Error").New(err.Error()))
					return
				}
				pr[0].Invoke(js.ValueOf(map[string]any{"msg": r["msg"], "conf": r["conf"], "expect": r["expect"]}))
			}()
			return nil
		}))
	}))
	js.Global().Set("hostVerify", js.FuncOf(func(_ js.Value, a []js.Value) any { // → Promise<отпечаток ключа хоста>
		args := make([]string, 5)
		for i := range args {
			if i < len(a) {
				args[i] = a[i].String()
			}
		}
		fp, err := pake.HostVerifyB64(args[0], args[1], args[2], args[3], args[4])
		if err != nil {
			return js.Global().Get("Promise").Call("reject", js.Global().Get("Error").New(err.Error()))
		}
		return js.Global().Get("Promise").Call("resolve", fp)
	}))
	js.Global().Set("clientSign", js.FuncOf(func(_ js.Value, a []js.Value) any { // (seed, host, localSDP, remoteSDP) → {seed, pub, sig}
		args := make([]string, 4)
		for i := range args {
			if i < len(a) && a[i].Type() == js.TypeString {
				args[i] = a[i].String()
			}
		}
		r, err := pake.ClientSignB64(args[0], args[1], args[2], args[3])
		if err != nil {
			return nil
		}
		o := js.Global().Get("Object").New()
		for k, v := range r {
			o.Set(k, v)
		}
		return o
	}))
	select {}
}
