package pake

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

// Ключ хоста (REQ-F-01, REQ-S-05): Ed25519, закрытый ключ не покидает хост.
// Сервер связывает ID с публичным ключом (подпись вызова при регистрации); клиент после CPace
// проверяет подпись хоста над DTLS-отпечатками обеих сторон и запоминает отпечаток ключа (TOFU).
// Требует ревью человеком (A13, A2 #10).

// RegisterMsg — что подписывает хост при регистрации на сервере.
func RegisterMsg(hostID, nonce string) []byte {
	return []byte("anypc-register-v1\n" + hostID + "\n" + nonce)
}

func identityMsg(hostID, fpClient, fpHost string) []byte {
	return []byte("anypc-host-v1\n" + hostID + "\n" + fpClient + "\n" + fpHost)
}

// HostSign — подпись хоста для клиента; привязка к DTLS-отпечаткам исключает повтор в другом соединении.
func HostSign(priv ed25519.PrivateKey, hostID, fpClient, fpHost string) []byte {
	return ed25519.Sign(priv, identityMsg(hostID, fpClient, fpHost))
}

func HostVerify(pub, sig []byte, hostID, fpClient, fpHost string) error {
	if len(pub) != ed25519.PublicKeySize || fpClient == "" || fpHost == "" || !ed25519.Verify(pub, identityMsg(hostID, fpClient, fpHost), sig) {
		return errors.New("pake: подпись хоста неверна")
	}
	return nil
}

// KeyFingerprint — короткий отпечаток ключа для людей: 16 байт SHA-256 группами по 4 hex.
func KeyFingerprint(pub []byte) string {
	h := sha256.Sum256(pub)
	s := hex.EncodeToString(h[:16])
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s[i : i+4])
	}
	return b.String()
}

// HostVerifyB64 — для JS (программа и WASM): проверка подписи хоста, возвращает отпечаток его ключа.
func HostVerifyB64(pubB64, sigB64, hostID, localSDP, remoteSDP string) (string, error) {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return "", err
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "", err
	}
	if err := HostVerify(pub, sig, hostID, Fingerprint(localSDP), Fingerprint(remoteSDP)); err != nil {
		return "", err
	}
	return KeyFingerprint(pub), nil
}

// Доверенный клиент (У3): клиент держит свой ключ Ed25519 на каждый хост и подписывает им те же DTLS-отпечатки.
// Хост закрепляет ключ после входа по паролю; с ним блокировка перебора и лимит незавершённых входов не мешают
// владельцу (пароль всё равно нужен). Подпись привязана к DTLS — повтор в другом соединении не пройдёт.
func clientMsg(hostID, fpClient, fpHost string) []byte {
	return []byte("anypc-client-v1\n" + hostID + "\n" + fpClient + "\n" + fpHost)
}

// ClientVerify — подпись клиента над DTLS-отпечатками (fpClient — его, fpHost — хоста).
func ClientVerify(pub, sig []byte, hostID, fpClient, fpHost string) bool {
	return len(pub) == ed25519.PublicKeySize && fpClient != "" && fpHost != "" && ed25519.Verify(pub, clientMsg(hostID, fpClient, fpHost), sig)
}

// ClientSignB64 — для веб-клиента (wasm): seed "" → новый ключ. Ответ: seed (хранит клиент), pub, sig — base64.
func ClientSignB64(seedB64, hostID, localSDP, remoteSDP string) (map[string]string, error) {
	b64 := base64.StdEncoding
	seed, err := b64.DecodeString(seedB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
	}
	k := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(k, clientMsg(hostID, Fingerprint(localSDP), Fingerprint(remoteSDP)))
	return map[string]string{"seed": b64.EncodeToString(seed), "pub": b64.EncodeToString(k.Public().(ed25519.PublicKey)), "sig": b64.EncodeToString(sig)}, nil
}

// «Снять» пропуск одним сообщением через хаб (Э3, решение владельца 8 A): мастер подписывает ключом хоста ID цели,
// время unix и случайный nonce; тело — pub ‖ время (8 байт BE) ‖ nonce ‖ подпись. Подпись самодостаточна (без
// DTLS): от повтора — окно времени и кэш nonce на цели (agent/pass.go). Требует ревью человеком (A13, A2 #10).
const (
	OffNonce = 16
	OffSize  = ed25519.PublicKeySize + 8 + OffNonce + ed25519.SignatureSize
)

func offMsg(hostID string, body []byte) []byte {
	return append([]byte("anypc-pass-off-v1\n"+hostID+"\n"), body[ed25519.PublicKeySize:ed25519.PublicKeySize+8+OffNonce]...)
}

// OffSign — тело «снять» на цель hostID ключом priv во время unix t с nonce (OffNonce байт).
func OffSign(priv ed25519.PrivateKey, hostID string, t int64, nonce []byte) []byte {
	b := append(bytes.Clone(priv.Public().(ed25519.PublicKey)), binary.BigEndian.AppendUint64(nil, uint64(t))...)
	b = append(b, nonce[:OffNonce]...)
	return append(b, ed25519.Sign(priv, offMsg(hostID, b))...)
}

// OffVerify — тело для цели hostID подписано ключом pub (первые 32 байта); ok — подпись верна.
func OffVerify(body []byte, hostID string) (pub ed25519.PublicKey, t int64, nonce []byte, ok bool) {
	if len(body) != OffSize {
		return nil, 0, nil, false
	}
	pub, sig := body[:ed25519.PublicKeySize], body[OffSize-ed25519.SignatureSize:]
	t = int64(binary.BigEndian.Uint64(body[ed25519.PublicKeySize:]))
	nonce = body[ed25519.PublicKeySize+8 : ed25519.PublicKeySize+8+OffNonce]
	return pub, t, nonce, ed25519.Verify(pub, offMsg(hostID, body), sig)
}
