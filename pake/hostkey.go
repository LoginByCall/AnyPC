package pake

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
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

// «Снять» пропуск одним сообщением через хаб (Э3, решение владельца 8 A). Цель выдаёт пропуску случайный id (OffID
// байт, в "ok" входа — внутри DTLS); мастер подписывает ключом хоста домен, ID цели и id пропуска: тело — pub ‖ id ‖
// подпись. Цель отвечает подписью ключа хоста над доменом ответа, ID, ключом просившего, id и статусом: тело — id ‖
// статус ‖ подпись (ответ одному члену M другому не годится: подпись — над его ключом).
// Часов и кэша нет: повтор снимает уже снятый пропуск (id нового — другой). Требует ревью человеком (A13, A2 #10).
const (
	OffID      = 16
	OffSize    = ed25519.PublicKeySize + OffID + ed25519.SignatureSize
	OffAckSize = OffID + 1 + ed25519.SignatureSize
)

func offMsg(hostID string, pid []byte) []byte {
	return append([]byte("anypc-pass-off-v1\n"+hostID+"\n"), pid...)
}

func offAckMsg(hostID string, req, pid []byte, st byte) []byte {
	return append(append(append([]byte("anypc-pass-off-ack-v1\n"+hostID+"\n"), req...), pid...), st)
}

// OffSign — тело «снять» пропуска pid (OffID байт) на цели hostID ключом priv.
func OffSign(priv ed25519.PrivateKey, hostID string, pid []byte) []byte {
	b := append(bytes.Clone(priv.Public().(ed25519.PublicKey)), pid[:OffID]...)
	return append(b, ed25519.Sign(priv, offMsg(hostID, pid[:OffID]))...)
}

// OffVerify — тело для цели hostID подписано ключом pub (первые 32 байта); ok — подпись верна.
func OffVerify(body []byte, hostID string) (pub ed25519.PublicKey, pid []byte, ok bool) {
	if len(body) != OffSize {
		return nil, nil, false
	}
	pub, pid = body[:ed25519.PublicKeySize], body[ed25519.PublicKeySize:ed25519.PublicKeySize+OffID]
	return pub, pid, ed25519.Verify(pub, offMsg(hostID, pid), body[OffSize-ed25519.SignatureSize:])
}

// OffAck — ответ цели hostID на «снять» пропуска pid ключом req (ed25519.PublicKeySize байт): dropped — снят сейчас,
// иначе такого пропуска у req нет.
func OffAck(priv ed25519.PrivateKey, hostID string, req, pid []byte, dropped bool) []byte {
	st := map[bool]byte{true: 1, false: 0}[dropped]
	return append(append(bytes.Clone(pid[:OffID]), st), ed25519.Sign(priv, offAckMsg(hostID, req, pid[:OffID], st))...)
}

// OffAckVerify — ответ подписан ключом хоста hostPub цели hostID, дан на «снять» ключа req и относится к пропуску
// pid; dropped — статус.
func OffAckVerify(hostPub, body []byte, hostID string, req, pid []byte) (dropped, ok bool) {
	if len(hostPub) != ed25519.PublicKeySize || len(req) != ed25519.PublicKeySize || len(body) != OffAckSize ||
		!bytes.Equal(body[:OffID], pid) || body[OffID] > 1 {
		return false, false
	}
	return body[OffID] == 1, ed25519.Verify(hostPub, offAckMsg(hostID, req, pid, body[OffID]), body[OffID+1:])
}

// Ключ X25519 из ключа хоста Ed25519 (Э4в, сверка без следа для хаба, agent/spseal.go): то же преобразование, что
// crypto_sign_ed25519_{sk,pk}_to_curve25519 в libsodium — закрытый скаляр = SHA-512(seed)[:32] (X25519 зажимает биты
// сам), открытый u = (1+y)/(1−y) mod p. Отдельного ключа в составе M не нужно: ключи членов там уже есть. [вывод]
// Одна пара для Ed25519 и X25519 — так в libsodium и age; совместная стойкость — Thormarker, 2021 («On using the
// same key pair for Ed25519 and an X25519 based KEM»). Требует ревью человеком (A13, A2 #10).

var p25519, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)

// XPriv — закрытый ключ X25519 ключа хоста priv.
func XPriv(priv ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	h := sha512.Sum512(priv.Seed())
	return ecdh.X25519().NewPrivateKey(h[:32])
}

// XPub — открытый ключ X25519 ключа Ed25519 pub (тот же, что XPriv(priv).PublicKey()). Открытые ключи не секретны —
// big.Int без постоянного времени годится.
func XPub(pub ed25519.PublicKey) (*ecdh.PublicKey, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("pake: ключ не Ed25519")
	}
	le := bytes.Clone(pub)
	le[31] &= 0x7f // старший бит — знак x
	slices.Reverse(le)
	y := new(big.Int).SetBytes(le)
	one := big.NewInt(1)
	d := new(big.Int).Sub(one, y)
	d.Mod(d, p25519)
	if y.Cmp(p25519) >= 0 || d.Sign() == 0 { // y = 1 — нейтральная точка
		return nil, errors.New("pake: ключ Ed25519 негодный")
	}
	u := new(big.Int).Add(one, y)
	u.Mul(u, d.ModInverse(d, p25519))
	u.Mod(u, p25519)
	b := u.FillBytes(make([]byte, 32))
	slices.Reverse(b)
	return ecdh.X25519().NewPublicKey(b)
}
