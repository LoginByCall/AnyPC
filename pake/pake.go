// Package pake — проверка пароля без его передачи (REQ-S-02): CPace (filippo.io/cpace, ristretto255)
// поверх уже установленного DTLS-канала, с привязкой к DTLS-отпечаткам обеих сторон и ID хоста
// и взаимным подтверждением ключа. Сервер сигнализации не видит ни пароля, ни его хэша; подмена
// DTLS (MITM на сервере) даёт разные отпечатки → разные ключи → отказ.
// Требует ревью человеком (A13, A2 #10).
package pake

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"filippo.io/cpace"
	"golang.org/x/crypto/argon2"
)

var ErrAuth = errors.New("pake: неверный пароль или подмена соединения")

// KDF — Argon2id(пароль, соль). Хост хранит только результат; клиент вычисляет его из пароля.
// ponytail: результат KDF эквивалентен паролю для входа (кража config.json = доступ); OPAQUE — если понадобится.
func KDF(pass string, salt []byte) []byte { return argon2.IDKey([]byte(pass), salt, 2, 64<<10, 2, 32) }

var fpRe = regexp.MustCompile(`(?m)^a=fingerprint:(\S+) ([0-9A-Fa-f:]+)\s*$`)

// Fingerprint — DTLS-отпечаток из SDP в виде "sha-256 AB:CD:…" ("" — нет).
func Fingerprint(sdp string) string {
	m := fpRe.FindStringSubmatch(sdp)
	if m == nil {
		return ""
	}
	return strings.ToLower(m[1]) + " " + strings.ToUpper(m[2])
}

func context(hostID, fpClient, fpHost string) *cpace.ContextInfo {
	return cpace.NewContextInfo("anypc-host:"+hostID, "anypc-client", []byte("anypc-auth-v1\n"+fpClient+"\n"+fpHost))
}

func confirm(key []byte, role string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("anypc-confirm-" + role))
	return h.Sum(nil)
}

// HostStart — первый шаг хоста; secret = KDF(пароль, соль) из настроек.
func HostStart(secret []byte, hostID, fpClient, fpHost string) ([]byte, *cpace.State, error) {
	if len(secret) == 0 || fpClient == "" || fpHost == "" {
		return nil, nil, errors.New("pake: нет пароля или DTLS-отпечатка")
	}
	return cpace.Start(hex.EncodeToString(secret), context(hostID, fpClient, fpHost))
}

// HostFinish проверяет ответ клиента; при успехе возвращает подтверждение хоста для клиента.
func HostFinish(st *cpace.State, msgB, clientConf []byte) ([]byte, error) {
	key, err := st.Finish(msgB)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(clientConf, confirm(key, "client")) {
		return nil, ErrAuth
	}
	return confirm(key, "host"), nil
}

// ClientRespond — шаг клиента. hostConf — ожидаемое подтверждение хоста (сравнить с присланным).
func ClientRespond(pass string, salt, msgA []byte, hostID, fpClient, fpHost string) (msgB, clientConf, hostConf []byte, err error) {
	if fpClient == "" || fpHost == "" {
		return nil, nil, nil, errors.New("pake: нет DTLS-отпечатка")
	}
	msgB, key, err := cpace.Exchange(hex.EncodeToString(KDF(pass, salt)), context(hostID, fpClient, fpHost), msgA)
	if err != nil {
		return nil, nil, nil, err
	}
	return msgB, confirm(key, "client"), confirm(key, "host"), nil
}

// ClientRespondB64 — ClientRespond для JS (программа и WASM): base64 на входе и выходе,
// отпечатки извлекаются из SDP своей стороны (localSDP) и хоста (remoteSDP).
func ClientRespondB64(pass, salt, msgA, hostID, localSDP, remoteSDP string) (map[string]string, error) {
	b64 := base64.StdEncoding
	s, err := b64.DecodeString(salt)
	if err != nil {
		return nil, err
	}
	m, err := b64.DecodeString(msgA)
	if err != nil {
		return nil, err
	}
	msgB, conf, expect, err := ClientRespond(pass, s, m, hostID, Fingerprint(localSDP), Fingerprint(remoteSDP))
	if err != nil {
		return nil, err
	}
	return map[string]string{"msg": b64.EncodeToString(msgB), "conf": b64.EncodeToString(conf), "expect": b64.EncodeToString(expect)}, nil
}
