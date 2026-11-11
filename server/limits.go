package main

// Лимиты памяти и соединений узла (приёмки 6–7, п. 2(в) аудита): потолки из памяти узла, общий и «на адрес» лимит TCP,
// буферы ядра, тяжёлые ответы (статика, загрузки) и срок их записи.

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"anypc/hub"
)

// HTTPConns — TCP-соединений сверх потолка WS (Д1″ приёмки-6, D5 приёмки-1): страница, сайт, загрузки, /turns, /hubs
// и простаивающие keep-alive. Их не видят ни MaxConns хаба, ни его лимиты «на адрес», поэтому всё TCP на порту —
// под общим лимитом; сверх него новое соединение ждёт в очереди ядра, пока не освободится место. На :80 — только он.
const HTTPConns = 256

// tcpLimit — всех TCP-соединений на порту сигнализации: WS плюс 10 % (не меньше HTTPConns) на HTTP.
func tcpLimit(conns int) int { return conns + max(conns/10, HTTPConns) }

// GoLimitPct — предел сборщика Go, % бюджета (Д3 приёмки-7). Остальное — буферы сокетов ядра, которых предел Go не
// видит: при 80 % (459 из 574 МиБ) встречный поток с offer 60 КБ на ядре E доводил cgroup до предела (Go 447 + sock 120).
const GoLimitPct = 70

// TCPPerAddr — TCP-соединений с одного адреса (IPv4, /64; /48 — ×10), сверх — закрыть сразу (Д2 приёмки-7). Без него
// 6000 молчащих соединений с одного адреса занимали весь общий лимит, и законный ждал 13–19 с. Больше ConnsPerIP хаба
// (100 WS): с адреса ходят ещё страница и загрузки. Loopback и частные — без лимита (свой узел за прокси).
const TCPPerAddr = 128

// RcvBuf, SndBuf — буферы ядра у каждого принятого соединения (Д1″ (в) приёмки-6, Д1 приёмки-7). По умолчанию ядро
// растит их до мегабайт на сокет: остановленный ответ (GET /pake.wasm, загрузка — клиент не читает) копил ≈1,5 МиБ
// на соединение, OOM за 2 с с одного адреса. Отдача 256 КиБ — ≈0,85 МБ/с на загрузку при RTT 300 мс; WS хаб
// снижает до hub.SndBuf. Входящий поток — сообщения ≤ 64 КБ и запросы: 32 КиБ.
const RcvBuf, SndBuf = 32 << 10, 256 << 10

// addrKeys — ключи лимитов «на адрес» (как у хаба); подменяется в опытах.
var addrKeys = hub.AddrKeys

// limitListener — не больше cap(sem) соединений одновременно (n+1-е ждёт в Accept, в очереди ядра) и не больше
// TCPPerAddr с адреса (сверх — закрыть сразу). Свой, а не netutil.LimitListener: его обёртка прячет *net.TCPConn,
// а hub ставит SndBuf захваченному WS через SetWriteBuffer — здесь он виден (limConn встраивает *net.TCPConn).
type limitListener struct {
	*net.TCPListener
	sem chan struct{}
	mu  sync.Mutex
	per map[string]int
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		l.sem <- struct{}{}
		c, err := l.AcceptTCP()
		if err != nil {
			<-l.sem
			return nil, err
		}
		ks := addrKeys(c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap())
		if !l.take(ks) {
			c.Close()
			<-l.sem
			continue
		}
		c.SetReadBuffer(RcvBuf)
		c.SetWriteBuffer(SndBuf)
		return &limConn{TCPConn: c, release: func() { l.give(ks); <-l.sem }}, nil
	}
}

// take занимает место на всех ключах адреса (все или ничего).
func (l *limitListener) take(ks []hub.AddrKey) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range ks {
		if l.per[k.Key] >= TCPPerAddr*k.Mul {
			return false
		}
	}
	for _, k := range ks {
		l.per[k.Key]++
	}
	return true
}

func (l *limitListener) give(ks []hub.AddrKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range ks {
		if l.per[k.Key]--; l.per[k.Key] <= 0 {
			delete(l.per, k.Key)
		}
	}
}

type limConn struct {
	*net.TCPConn
	once    sync.Once
	release func()
}

func (c *limConn) Close() error {
	err := c.TCPConn.Close()
	c.once.Do(c.release)
	return err
}

// listen — TCP на addr под limitListener на n соединений.
func listen(addr string, n int) *limitListener {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	return &limitListener{TCPListener: l.(*net.TCPListener), sem: make(chan struct{}, n), per: map[string]int{}}
}

// Тяжёлые ответы — статика и загрузки (страница 165 КБ, pake.wasm 4 МБ, AnyPC.exe): у каждого буфер ядра до 2 × SndBuf,
// и остановленный ответ держит его, пока не истечёт StallWrite. Одновременно — не больше HeavyTotal, с адреса —
// HeavyPerAddr (/48 — ×10); сверх — ждут до HeavyWait, затем 503. Браузеру хватает: остальное он ставит в очередь сам.
const (
	HeavyTotal, HeavyPerAddr = 32, 4
	HeavyWait                = 10 * time.Second
	// StallWrite — тяжёлый ответ без продвижения (кусок stallChunk не ушёл в буфер ядра) столько — соединение рвётся:
	// медленный честный клиент докачивает (от ≈0,5 КБ/с), остановленный освобождает место за ≈30 с.
	StallWrite = 30 * time.Second
	stallChunk = 16 << 10
)

type heavyLim struct {
	mu    sync.Mutex
	total int
	per   map[string]int
}

var heavyNow = &heavyLim{per: map[string]int{}}

func (l *heavyLim) try(ks []hub.AddrKey) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= HeavyTotal {
		return false
	}
	for _, k := range ks {
		if l.per[k.Key] >= HeavyPerAddr*k.Mul {
			return false
		}
	}
	l.total++
	for _, k := range ks {
		l.per[k.Key]++
	}
	return true
}

func (l *heavyLim) done(ks []hub.AddrKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	for _, k := range ks {
		if l.per[k.Key]--; l.per[k.Key] <= 0 {
			delete(l.per, k.Key)
		}
	}
}

// acquire ждёт места до HeavyWait (или конца запроса); false — не дождались.
func (l *heavyLim) acquire(ctx context.Context, ks []hub.AddrKey) bool {
	deadline := time.Now().Add(HeavyWait)
	for !l.try(ks) {
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
	return true
}

// heavy — обёртка тяжёлого ответа: лимит одновременных (heavyNow) и срок записи по продвижению (StallWrite).
func heavy(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ks := addrKeys(hub.ClientAddr(r))
		if !heavyNow.acquire(r.Context(), ks) {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		defer heavyNow.done(ks)
		rc := http.NewResponseController(w)
		defer rc.SetWriteDeadline(time.Time{}) // keep-alive: следующий ответ на этом соединении — без старого срока
		h.ServeHTTP(stallWriter{w, rc}, r)
	})
}

// stallWriter пишет кусками stallChunk, ставя срок StallWrite перед каждым.
type stallWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
}

func (w stallWriter) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		k := min(len(p), stallChunk)
		w.rc.SetWriteDeadline(time.Now().Add(StallWrite))
		m, err := w.ResponseWriter.Write(p[:k])
		if n += m; err != nil {
			return n, err
		}
		p = p[k:]
	}
	return n, nil
}

// limits — что действует на узле.
type limits struct {
	conns, tcp int
	goLimit    int64 // 0 — не ставить
}

// plan — потолки из бюджета памяти: явный -maxconns важнее; предел Go — GoLimitPct бюджета, если GOMEMLIMIT не задан.
func plan(maxConns int, budget int64, gomemlimit string) limits {
	l := limits{conns: cmp.Or(maxConns, hub.ConnsFor(budget))}
	l.tcp = tcpLimit(l.conns)
	if gomemlimit == "" && budget > 0 {
		l.goLimit = budget * GoLimitPct / 100
	}
	return l
}

// memBudget — память узла для хаба: предел своей cgroup и её предков (наименьший; cgroup v2 — memory.max,
// v1 — memory/…/memory.limit_in_bytes; MemoryMax unit-файла — у прода 60 % ОЗУ), если он меньше ОЗУ; иначе 60 %
// MemTotal; 0 — не узнать (не Linux: потолок — MinConns, журнал скажет «неизвестен»). from — откуда взято.
func memBudget(read func(string) ([]byte, error)) (budget int64, from string) {
	var total int64
	if b, err := read("/proc/meminfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "MemTotal:" {
				if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					total = kb << 10
				}
			}
		}
	}
	if b, err := read("/proc/self/cgroup"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.SplitN(l, ":", 3)
			if len(f) != 3 {
				continue
			}
			root, file := "/sys/fs/cgroup", "memory.max" // v2: «0::/путь»
			if f[0] != "0" || f[1] != "" {
				if !strings.Contains(","+f[1]+",", ",memory,") {
					continue
				}
				root, file = "/sys/fs/cgroup/memory", "memory.limit_in_bytes" // v1: «N:memory:/путь»
			}
			for dir := path.Clean(f[2]); ; dir = path.Dir(dir) {
				p := path.Join(root, dir, file)
				if v, err := read(p); err == nil {
					if n, err := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64); err == nil && n > 0 && (budget == 0 || n < budget) {
						budget, from = n, p
					}
				}
				if dir == "/" || dir == "." {
					break
				}
			}
		}
	}
	if budget > 0 && (total == 0 || budget < total) {
		return budget, from
	}
	if total > 0 {
		return total * 6 / 10, "60 % MemTotal"
	}
	return 0, "не определена"
}

// memLine — строка журнала при старте: откуда потолки и что действует.
func memLine(budget int64, from string, goLimit int64, conns, tcp int) string {
	return fmt.Sprintf("память: бюджет %s (%s), предел Go %s; соединений сигнализации %d, TCP %d (с адреса %d)", mib(budget), from, mib(goLimit), conns, tcp, TCPPerAddr)
}

// mib — байты для журнала; без предела (math.MaxInt64 от SetMemoryLimit) и 0 — словами.
func mib(n int64) string {
	switch {
	case n <= 0:
		return "неизвестен"
	case n >= 1<<62:
		return "нет"
	}
	return strconv.FormatInt(n>>20, 10) + " МиБ"
}
