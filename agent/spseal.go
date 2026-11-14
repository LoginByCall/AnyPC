package agent

// Э4в (решение владельца 2026-11-14, B): connect сверки состава хаб не отличает от обычного и ключей членов не видит.
// ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md A13: криптография, A2 #10), в т.ч. вывод X25519 из Ed25519 (pake.XPriv/XPub).
//
// Каждый connect нового клиента (браузер, вступление, пропуск, сверка) несёт поле "sx" — sxLen байт. У сверки это
// доказательство члена, запечатанное к ключу хоста цели; у остальных — случайные байты. Схема — статический X25519
// (ключи выводятся из ключей хостов Ed25519, pake.XPriv/XPub) + HKDF-SHA256 + AES-256-GCM, только stdlib:
//
//	S   = X25519(член, цель)                          — общий секрет пары; знают только член и цель
//	k   = HKDF(S, соль, "anypc-space-sync-seal-v1\0" ‖ ID цели) → c2h ‖ h2c (по 32 байта)
//	sx  = соль(16) ‖ AES-GCM(c2h, время unix 8 байт BE)                    — в connect
//	"a" = …, "sx": nonce(12) ‖ AES-GCM(h2c, nonce, статус 1 байт, AAD = отпечатки DTLS) — в канале auth, первый "a"
//
// nonce ответа случаен: хаб может подать перехваченный sx своими connect сколько угодно раз (при skew соль в кэш не
// попадает), и хост на каждый шифрует статус тем же h2c. С постоянным nonce это повтор гаммы (C0⊕C1 = OK⊕busy —
// сверка узнана) и ключ GHASH по двум тегам — подделка «ok» под отпечатки посредника и ключ члена в "b" (приёмка
// Э4в, Б1). В направлении c2h повтора нет: соль своя у каждого connect (sxMake), и ключом c2h шифруется одно сообщение;
// повтор sx хабом даёт тот же шифртекст, нового не раскрывает.
//
// Почему не эфемерный X25519: открытый ключ X25519 на проводе отличим от случайных байт (старший бит всегда 0, точка
// всегда на кривой, а не на кручении — символ Лежандра), а Elligator2 в stdlib нет. Статический секрет пары и случайная
// соль дают поле, неотличимое от случайного. Хост ищет члена перебором ключей своего M (SyncKeys): общие секреты X25519
// в кэше (sxPeers), перебор — всегда полный, не короче sxPad (sxOpenPeers, Б2: время не выдаёт ни сверку, ни размер).
//
// Хост открыл sx и время в пределах syncSkew, соли ещё не видел, место ключа свободно — сверка: своё место (вне места
// сессии, maxPending и блокировки перебора), offer как обычному. Иначе — обычный connect (обычные ответы "busy",
// "locked", offer), а в "a" — статус под h2c (skew/busy) или случайные байты, если не открылось. Исключение одно:
// идёт сессия — сверка отвечает тем же, что обычный connect без ключа ("busy" или "locked"), иначе хаб, сам получив
// "busy", узнал бы сверку по offer. Под блокировкой перебора и при занятых местах входа (maxPending) сверка offer
// получает (посторонний не должен мешать сверке, решение владельца A) — в эти минуты хаб, сравнив с отказами обычным,
// её узнает. Неотличимость — только против пассивного хаба: активный узнаёт сверку пробой мест (после чужого connect
// три своих: "busy" на третьем — чужой был обычным, offer на всех — сверкой), SECURITY.md.
//
// Клиент открывает "sx" из "a" своими отпечатками DTLS: статус ok — сверка ("b" и дальше, spsync.go); skew/busy —
// отказ; не открылось — {"t":"who"} → хост {"t":"who",pub,sig} (HostSign над отпечатками, как в "ok"): ключ тот,
// что в M, — цель не считает этот ПК членом (ErrSpaceRefused), другой — под ID другой ПК (ErrSpaceIDKey, С4). Ключ
// хоста хаб и так знает (регистрация), так что "who" любому клиенту ничего не раскрывает.
//
// Повтор: соль открытого sx помнится, пока его время в окне syncSkew (sxSeen) — повтор хабом идёт как обычный
// connect с "busy" в "a". После перезапуска цели кэш пуст: повтор в окне ±10 мин занимает место члена до authWait, как и до Э4в.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync/atomic"
	"time"

	"anypc/pake"
)

const (
	sxSaltLen = 16
	sxLen     = sxSaltLen + 8 + 16 // соль ‖ AES-GCM(время): в connect
	sxALen    = 12 + 1 + 16        // nonce ‖ AES-GCM(статус): в первом "a" хоста
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

// sxNonce — нулевой, только для c2h: ключ из HKDF с одноразовой солью клиента, им шифруется одно сообщение (время).
// Ответ h2c — со случайным nonce (answer): хост шифрует им столько раз, сколько хаб повторит sx.
var sxNonce = make([]byte, 12)

// sxInfo — info HKDF: ключи привязаны к ID цели.
const sxInfo = "anypc-space-sync-seal-v1\x00"

// sxPad — перебор в sxOpenPeers не короче стольких ключей: столько бывает в M с ветвью раскола (app: spaceMaxMembers
// 32 × 2). Добивка пустышками — время перебора не выдаёт размер состава (Б2).
const sxPad = 64

// sxPeer — ключ члена и статичный общий секрет X25519 пары «член — этот хост». ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (A13): по
// чувствительности s равен закрытому ключу (им открываются доказательства этого члена) — только в памяти, на диск не
// пишется, в журнал не попадает. pub nil — пустышка добивки.
type sxPeer struct {
	pub ed25519.PublicKey
	s   []byte
}

var sxDummy = sxPeer{s: sxRand(32)} // секрет пустышки случаен: подобрать к нему sx нельзя, да и pub nil — не член

// Тест (Б2): число X25519 и Open — работа хоста не зависит ни от исхода, ни от позиции члена в составе.
var sxECDHs, sxOpens atomic.Int64

// sxShared — статичный общий секрет X25519 закрытого x и ключа Ed25519 peer.
func sxShared(x *ecdh.PrivateKey, peer ed25519.PublicKey) ([]byte, error) {
	sxECDHs.Add(1)
	u, err := pake.XPub(peer)
	if err != nil {
		return nil, err
	}
	return x.ECDH(u) // нулевой общий секрет (точка малого порядка) — ошибка
}

// sxDerive — c2h, h2c из общего секрета s для цели hostID и соли salt.
func sxDerive(s []byte, hostID string, salt []byte) (c2h, h2c []byte) {
	k, _ := hkdf.Key(sha256.New, s, salt, sxInfo+hostID, 64) // ошибка только при длине > 255·32
	return k[:32], k[32:]
}

// sxKeys — c2h, h2c пары (own, peer) для цели hostID и соли salt.
func sxKeys(own ed25519.PrivateKey, peer ed25519.PublicKey, hostID string, salt []byte) (c2h, h2c []byte, err error) {
	x, err := pake.XPriv(own)
	if err != nil {
		return nil, nil, err
	}
	s, err := sxShared(x, peer)
	if err != nil {
		return nil, nil, err
	}
	c2h, h2c = sxDerive(s, hostID, salt)
	return c2h, h2c, nil
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

// sxPeersOf — общие секреты хоста own с keys без кэша; негодные ключи пропускаются.
func sxPeersOf(own ed25519.PrivateKey, keys []ed25519.PublicKey) []sxPeer {
	x, err := pake.XPriv(own)
	if err != nil {
		return nil
	}
	var out []sxPeer
	for _, k := range keys {
		if s, err := sxShared(x, k); err == nil {
			out = append(out, sxPeer{pub: k, s: s})
		}
	}
	return out
}

// sxOpen — хост own: чей из keys этот sx; t — время клиента. ok=false — случайные байты или не член.
func sxOpen(own ed25519.PrivateKey, keys []ed25519.PublicKey, hostID string, sx []byte) (pub ed25519.PublicKey, t int64, h2c []byte, ok bool) {
	return sxOpenPeers(sxPeersOf(own, keys), hostID, sx)
}

// sxOpenPeers — перебор без раннего выхода: HKDF и Open для каждого ключа и пустышек до sxPad — одна и та же работа,
// открылся sx или нет и на каком ключе (Б2: иначе хаб по времени connect→offer отличал сверку от обычного connect и
// узнавал размер состава). Остаётся разница в единицы микросекунд: расшифровка 8 байт при совпадении тега и кэш
// повтора (sxSeen) у сверки — на фоне миллисекунд сети.
func sxOpenPeers(peers []sxPeer, hostID string, sx []byte) (pub ed25519.PublicKey, t int64, h2c []byte, ok bool) {
	if len(sx) != sxLen {
		return nil, 0, nil, false
	}
	salt := sx[:sxSaltLen]
	for i := range max(len(peers), sxPad) {
		p := sxDummy
		if i < len(peers) {
			p = peers[i]
		}
		c2h, h := sxDerive(p.s, hostID, salt)
		sxOpens.Add(1)
		pt, err := sxGCM(c2h).Open(nil, sxNonce, sx[sxSaltLen:], nil)
		if err == nil && p.pub != nil && !ok {
			pub, t, h2c, ok = p.pub, int64(binary.BigEndian.Uint64(pt)), h, true
		}
	}
	return pub, t, h2c, ok
}

// sxPeers — общие секреты этого хоста с keys из кэша (sxCache): X25519 считается только для новых ключей; ключи,
// которых в составе больше нет, из кэша уходят; смена ключа хоста — кэш заново. Под sxMu, не под a.mu: первый
// пересчёт после смены состава — до 64 X25519.
func (a *Agent) sxPeers(keys []ed25519.PublicKey) []sxPeer {
	a.sxMu.Lock()
	defer a.sxMu.Unlock()
	me := a.Key.Public().(ed25519.PublicKey)
	if !bytes.Equal(a.sxHost, me) {
		a.sxHost, a.sxCache = bytes.Clone(me), nil
	}
	var x *ecdh.PrivateKey
	next := make(map[string][]byte, len(keys))
	out := make([]sxPeer, 0, len(keys))
	for _, k := range keys {
		s, hit := a.sxCache[string(k)]
		if !hit {
			if x == nil {
				var err error
				if x, err = pake.XPriv(a.Key); err != nil {
					return nil
				}
			}
			var err error
			if s, err = sxShared(x, k); err != nil {
				continue
			}
		}
		next[string(k)] = s
		out = append(out, sxPeer{pub: k, s: s})
	}
	a.sxCache = next
	return out
}

// sxAAD — отпечатки DTLS (клиента, хоста): статус не перенести в другое соединение (посредник в DTLS его не откроет).
func sxAAD(fpc, fph string) []byte { return []byte(fpc + "\x00" + fph) }

// answer — поле sx первого "a" хоста; s nil — случайные байты той же длины.
func (s *sxSeal) answer(fpc, fph string) []byte {
	if s == nil {
		return sxRand(sxALen)
	}
	n := sxRand(12)
	return sxGCM(s.h2c).Seal(n, n, []byte{s.status}, sxAAD(fpc, fph))
}

// sxStatus — клиент: статус из sx первого "a"; ok=false — не открылось (не тот ПК, не член там или посредник).
func sxStatus(h2c, sx []byte, fpc, fph string) (byte, bool) {
	if len(sx) != sxALen {
		return 0, false
	}
	pt, err := sxGCM(h2c).Open(nil, sx[:12], sx[12:], sxAAD(fpc, fph))
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
	pub, t, h2c, ok := sxOpenPeers(a.sxPeers(a.SpaceSync.SyncKeys()), a.ID, sx)
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
