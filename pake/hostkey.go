package pake

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
