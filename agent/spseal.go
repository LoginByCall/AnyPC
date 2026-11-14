package agent

// Э4в (решение владельца 2026-11-14, B): connect сверки состава хаб не отличает от обычного и ключей членов не видит.
// ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md A13: криптография, A2 #10).
//
// Каждый connect нового клиента (браузер, вступление, пропуск, сверка) несёт поле "sx" — sxLen байт. У сверки это
// доказательство члена, запечатанное к ключу хоста цели; у остальных — случайные байты. Схема — статический X25519
// (ключи выводятся из ключей хостов Ed25519, pake.XPriv/XPub) + HKDF-SHA256 + AES-256-GCM, только stdlib:
//
//	S   = X25519(член, цель)                          — общий секрет пары; знают только член и цель
//	k   = HKDF(S, соль, "anypc-space-sync-seal-v1\0" ‖ ID цели) → c2h ‖ h2c (по 32 байта)
//	sx  = соль(16) ‖ AES-GCM(c2h, время unix 8 байт BE)                    — в connect
//	"a" = …, "sx": AES-GCM(h2c, статус 1 байт, AAD = отпечатки DTLS)         — в канале auth, первый "a" хоста
//
// Почему не эфемерный X25519: открытый ключ X25519 на проводе отличим от случайных байт (старший бит всегда 0, точка
// всегда на кривой, а не на кручении — символ Лежандра), а Elligator2 в stdlib нет. Статический секрет пары и случайная
// соль дают поле, неотличимое от случайного. Хост ищет члена перебором ключей своего M (SyncKeys) — доли миллисекунды.
//
// Хост открыл sx и время в пределах syncSkew, соли ещё не видел, место ключа свободно — сверка: своё место (вне места
// сессии, maxPending и блокировки перебора), offer как обычному. Иначе — обычный connect (обычные ответы "busy",
// "locked", offer), а в "a" — статус под h2c (skew/busy) или случайные байты, если не открылось. Исключение одно:
// идёт сессия — сверка отвечает тем же, что обычный connect без ключа ("busy" или "locked"), иначе хаб, сам получив
// "busy", узнал бы сверку по offer. Под блокировкой перебора и при занятых местах входа (maxPending) сверка offer
// получает (посторонний не должен мешать сверке) — в эти минуты хаб, сравнив с отказами обычным, её узнает (SECURITY.md).
//
// Клиент открывает "sx" из "a" своими отпечатками DTLS: статус ok — сверка ("b" и дальше, spsync.go); skew/busy —
// отказ; не открылось — {"t":"who"} → хост {"t":"who",pub,sig} (HostSign над отпечатками, как в "ok"): ключ тот,
// что в M, — цель не считает этот ПК членом (ErrSpaceRefused), другой — под ID другой ПК (ErrSpaceIDKey, С4). Ключ
// хоста хаб и так знает (регистрация), так что "who" любому клиенту ничего не раскрывает.
//
// Повтор: соль открытого sx помнится, пока его время в окне syncSkew (sxSeen) — повтор хабом идёт как обычный
// connect с "busy" в "a". После перезапуска цели кэш пуст: повтор в окне ±10 мин занимает место члена до authWait, как и до Э4в.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"anypc/pake"
)

const (
	sxSaltLen = 16
	sxLen     = sxSaltLen + 8 + 16 // соль ‖ AES-GCM(время): в connect
	sxALen    = 1 + 16             // AES-GCM(статус): в первом "a" хоста
	sxSeenMax = 4096               // солей в кэше повтора; больше — новые сверки идут как обычный connect
)

// Статус сверки в "a" (под h2c).
const (
	sxOK   byte = 1 + iota // место сверки выделено
	sxSkew                 // часы расходятся больше syncSkew
	sxBusy                 // место ключа занято или повтор
)

// sxSeal — ответ хоста в "a" сессии, чей connect открылся; nil — в "a" случайные байты.
type sxSeal struct {
	h2c    []byte
	status byte
}

func sxRand(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func sxGCM(k []byte) cipher.AEAD {
	b, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(b)
	return g
}

// sxNonce — нулевой: ключи из HKDF с одноразовой солью, каждым ключом шифруется одно сообщение.
var sxNonce = make([]byte, 12)

// sxKeys — c2h, h2c пары (own, peer) для цели hostID и соли salt.
func sxKeys(own ed25519.PrivateKey, peer ed25519.PublicKey, hostID string, salt []byte) (c2h, h2c []byte, err error) {
	x, err := pake.XPriv(own)
	if err != nil {
		return nil, nil, err
	}
	u, err := pake.XPub(peer)
	if err != nil {
		return nil, nil, err
	}
	s, err := x.ECDH(u)
	if err != nil {
		return nil, nil, err
	}
	k, err := hkdf.Key(sha256.New, s, salt, "anypc-space-sync-seal-v1\x00"+hostID, 64)
	if err != nil {
		return nil, nil, err
	}
	return k[:32], k[32:], nil
}

// sxMake — клиент (член own) → цель hostID с ключом host: поле sx connect и ключ ответа h2c.
func sxMake(own ed25519.PrivateKey, host ed25519.PublicKey, hostID string, now int64) (sx, h2c []byte, err error) {
	salt := sxRand(sxSaltLen)
	c2h, h2c, err := sxKeys(own, host, hostID, salt)
	if err != nil {
		return nil, nil, err
	}
	return sxGCM(c2h).Seal(salt, sxNonce, binary.BigEndian.AppendUint64(nil, uint64(now)), nil), h2c, nil
}

// sxOpen — хост own: чей из keys этот sx; t — время клиента. ok=false — случайные байты или не член.
func sxOpen(own ed25519.PrivateKey, keys []ed25519.PublicKey, hostID string, sx []byte) (pub ed25519.PublicKey, t int64, h2c []byte, ok bool) {
	if len(sx) != sxLen {
		return nil, 0, nil, false
	}
	salt := sx[:sxSaltLen]
	for _, k := range keys {
		c2h, h, err := sxKeys(own, k, hostID, salt)
		if err != nil {
			continue
		}
		if pt, err := sxGCM(c2h).Open(nil, sxNonce, sx[sxSaltLen:], nil); err == nil {
			return k, int64(binary.BigEndian.Uint64(pt)), h, true
		}
	}
	return nil, 0, nil, false
}

// sxAAD — отпечатки DTLS (клиента, хоста): статус не перенести в другое соединение (посредник в DTLS его не откроет).
func sxAAD(fpc, fph string) []byte { return []byte(fpc + "\x00" + fph) }

// answer — поле sx первого "a" хоста; s nil — случайные байты той же длины.
func (s *sxSeal) answer(fpc, fph string) []byte {
	if s == nil {
		return sxRand(sxALen)
	}
	return sxGCM(s.h2c).Seal(nil, sxNonce, []byte{s.status}, sxAAD(fpc, fph))
}

// sxStatus — клиент: статус из sx первого "a"; ok=false — не открылось (не тот ПК, не член там или посредник).
func sxStatus(h2c, sx []byte, fpc, fph string) (byte, bool) {
	if len(sx) != sxALen {
		return 0, false
	}
	pt, err := sxGCM(h2c).Open(nil, sxNonce, sx, sxAAD(fpc, fph))
	if err != nil || len(pt) != 1 {
		return 0, false
	}
	return pt[0], true
}

// sxCheck — хост: connect с sx. nil — не открылось (обычный connect, в "a" случайные байты). Иначе ключ члена и
// ответ; status sxOK — соль записана в кэш повтора, место выделяет вызывающий.
func (a *Agent) sxCheck(sx []byte) (ed25519.PublicKey, *sxSeal) {
	if a.SpaceSync == nil || len(sx) != sxLen {
		return nil, nil
	}
	pub, t, h2c, ok := sxOpen(a.Key, a.SpaceSync.SyncKeys(), a.ID, sx)
	if !ok {
		return nil, nil
	}
	seal := &sxSeal{h2c: h2c, status: sxOK}
	now := time.Now()
	if now.Sub(time.Unix(t, 0)).Abs() > syncSkew {
		seal.status = sxSkew
		return pub, seal
	}
	salt := string(sx[:sxSaltLen])
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, until := range a.sxSeen {
		if now.After(until) {
			delete(a.sxSeen, k)
		}
	}
	if _, seen := a.sxSeen[salt]; seen || len(a.sxSeen) >= sxSeenMax {
		seal.status = sxBusy
		return pub, seal
	}
	if a.sxSeen == nil {
		a.sxSeen = map[string]time.Time{}
	}
	a.sxSeen[salt] = time.Unix(t, 0).Add(syncSkew) // позже — не пройдёт по времени
	return pub, seal
}
