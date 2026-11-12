package hub

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

// Day — суточная сводка узла (MONITORING.md): только суммы, без ID и IP (PRIVACY.md «Статистика»).
type Day struct {
	Day        string         `json:"day"`                 // UTC, 2006-01-02
	Hosts      int            `json:"hosts"`               // разных хостов за сутки
	HostsMax   int            `json:"hosts_max"`           // хостов в сети одновременно, максимум
	ClientsMax int            `json:"clients_max"`         // клиентов в сети одновременно, максимум
	Restarted  bool           `json:"restarted,omitempty"` // узел перезапускался в эти сутки: hosts завышен на тех, кто был в сети до перезапуска
	N          map[string]int `json:"n"`                   // события: new_id, connect, offer, answer, error, not_found, client_app, client_web, dl/<файл>…
	OS         map[string]int `json:"os"`                  // разных хостов по «ОС версия»; старые программы — «? ?»
}

// MaxKeys — потолок разных ключей в N и OS за сутки: строки от клиентов (имя файла, версия) не раздувают память.
const MaxKeys = 200

type stats struct {
	mu    sync.Mutex
	d     Day
	salt  [16]byte
	seen  map[[8]byte]bool // хэши ID хостов за сутки с солью суток; соль и множество — только в памяти
	hosts int              // в сети сейчас
	cl    int
	done  []Day // завершённые сутки, ещё не записанные StatsLoop
}

// roll — новые сутки: прошлые — в очередь на запись, соль меняется (вчерашние хэши не сопоставить с сегодняшними).
func (s *stats) roll(now time.Time) {
	day := now.UTC().Format(time.DateOnly)
	if s.d.Day == day {
		return
	}
	if s.d.Day != "" {
		s.done = append(s.done, s.d)
	}
	s.d = Day{Day: day, HostsMax: s.hosts, ClientsMax: s.cl, N: map[string]int{}, OS: map[string]int{}}
	s.seen = map[[8]byte]bool{}
	rand.Read(s.salt[:])
}

func (s *stats) count(m map[string]int, k string, n int) {
	if _, ok := m[k]; ok || len(m) < MaxKeys {
		m[k] += n
	} else {
		m["other"] += n
	}
}

// Count — событие за сутки (n раз).
func (h *Hub) Count(key string, n int) {
	s := &h.st
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roll(time.Now())
	s.count(s.d.N, key, n)
}

// online — хост/клиент вошёл (+1) или ушёл (-1); у вошедшего хоста учесть ID и «ОС версия».
func (h *Hub) online(host bool, id, osver string, d int) {
	s := &h.st
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roll(time.Now())
	if !host {
		s.cl += d
		s.d.ClientsMax = max(s.d.ClientsMax, s.cl)
		return
	}
	s.hosts += d
	s.d.HostsMax = max(s.d.HostsMax, s.hosts)
	if d < 0 {
		return
	}
	sum := sha256.Sum256(append(s.salt[:], id...))
	if k := [8]byte(sum[:8]); !s.seen[k] {
		s.seen[k] = true
		s.d.Hosts++
		s.count(s.d.OS, osver, 1)
	}
}

// osVer — «ОС версия» из ?os=&v= хоста; чужое и пустое — «?».
func osVer(osName, v string) string {
	ok := func(s string, n int) bool {
		return s != "" && len(s) <= n && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789.-") == ""
	}
	if !ok(osName, 10) {
		osName = "?"
	}
	if !ok(v, 24) {
		v = "?"
	}
	return osName + " " + v
}

// StatsLoop — раз в every пишет текущие сутки в <dir>/stats-today.json, завершённые — строкой в <dir>/stats.jsonl.
// При старте подхватывает сегодняшний файл (перезапуск при выпуске не обнуляет сутки; множество ID — нет, см. Restarted).
func (h *Hub) StatsLoop(ctx context.Context, dir string, every time.Duration) {
	today, all := dir+"/stats-today.json", dir+"/stats.jsonl"
	s := &h.st
	s.mu.Lock()
	s.roll(time.Now())
	if b, err := os.ReadFile(today); err == nil {
		var d Day
		if json.Unmarshal(b, &d) == nil && d.N != nil && d.OS != nil {
			if d.Day == s.d.Day {
				d.Restarted = true
				d.HostsMax, d.ClientsMax = max(d.HostsMax, s.d.HostsMax), max(d.ClientsMax, s.d.ClientsMax)
				for k, n := range s.d.N { // события с запуска до этой строки
					d.N[k] += n
				}
				s.d = d
			} else if d.Day < s.d.Day { // узел стоял в полночь: прошлые сутки не дописаны
				s.done = append([]Day{d}, s.done...)
			}
		}
	}
	s.mu.Unlock()
	for {
		s.mu.Lock()
		s.roll(time.Now())
		done := s.done
		s.done = nil
		cur, _ := json.Marshal(s.d)
		s.mu.Unlock()
		var lines []byte
		for _, d := range done {
			b, _ := json.Marshal(d)
			lines = append(append(lines, b...), '\n')
		}
		if f, err := os.OpenFile(all, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			f.Write(lines) // пустой — только создать файл
			f.Close()
		}
		if os.WriteFile(today+".tmp", cur, 0o600) == nil {
			os.Rename(today+".tmp", today)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}
