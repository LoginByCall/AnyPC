// anypc-probe — внешняя проверка узлов AnyPC (MONITORING.md). Запуск — таймер systemd на третьем узле (US):
// лендинг, хабы (VERSION, сигнализация, срок сертификата), выделение адреса на ретрансляторах TURN.
// О смене состояния — сообщение в Telegram (TG_TOKEN, TG_CHAT из окружения); сбой — после двух запусков подряд.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"anypc/hub"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/pion/turn/v5"
)

// CertDays — сертификат истекает раньше — сбой (autocert продлевает за 30 дней).
const CertDays = 14

func main() {
	site := flag.String("site", "www.anypc.org", "лендинг")
	hubs := flag.String("hubs", "hk.anypc.org,ru.anypc.org", "хабы через запятую")
	turns := flag.String("turn", "hk.anypc.org,ru.anypc.org,us.anypc.org", "ретрансляторы TURN через запятую")
	conf := flag.String("turnconf", "/etc/turnserver.conf", "откуда взять static-auth-secret")
	state := flag.String("state", "/var/lib/anypc-probe/state.json", "состояние между запусками")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cl := &http.Client{Timeout: 20 * time.Second}
	bad := map[string]string{}
	if err := checkSite(ctx, cl, "https://"+*site); err != nil {
		bad[*site] = err.Error()
	}
	vers := map[string]string{}
	for _, h := range strings.Split(*hubs, ",") {
		v, err := checkHub(ctx, cl, "https://"+h)
		if err != nil {
			bad[h] = err.Error()
		} else {
			vers[h] = v
		}
	}
	if e := sameVersion(vers); e != "" {
		bad["версии"] = e
	}
	b, _ := os.ReadFile(*conf)
	m := regexp.MustCompile(`(?m)^static-auth-secret=(\S+)`).FindSubmatch(b)
	if m == nil {
		bad["turn"] = "нет static-auth-secret в " + *conf
	}
	for _, t := range strings.Split(*turns, ",") {
		if m == nil {
			break
		}
		if err := checkTURN(ctx, t+":3478", string(m[1])); err != nil {
			bad["turn "+t] = err.Error()
		}
	}

	var st State
	if b, err := os.ReadFile(*state); err == nil {
		json.Unmarshal(b, &st)
	}
	now := time.Now()
	msg, next := st.Next(bad, now)
	log.Printf("сбоев: %d %v", len(bad), bad)
	if msg != "" {
		if err := tg(ctx, cl, os.Getenv("TG_TOKEN"), os.Getenv("TG_CHAT"), msg); err != nil {
			log.Print("telegram: ", err) // состояние не сохраняем — сообщение повторится в следующий запуск
			return
		}
	}
	b, _ = json.Marshal(next)
	if err := os.WriteFile(*state, b, 0o600); err != nil {
		log.Print(err)
	}
}

// get — тело ответа 200; сертификат, истекающий раньше CertDays, — ошибка.
func get(ctx context.Context, cl *http.Client, u string) (string, error) {
	r, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	resp, err := cl.Do(r)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		if d := time.Until(resp.TLS.PeerCertificates[0].NotAfter); d < CertDays*24*time.Hour {
			return "", fmt.Errorf("сертификат истекает через %.0f дн.", d.Hours()/24)
		}
	}
	return string(b), nil
}

func checkSite(ctx context.Context, cl *http.Client, base string) error {
	b, err := get(ctx, cl, base+"/")
	if err == nil && !strings.Contains(b, `id="get"`) {
		err = fmt.Errorf("лендинг без блока загрузок")
	}
	return err
}

// checkHub — VERSION на зеркале и сигнализация: клиентский WS получает hello с серверами ICE.
func checkHub(ctx context.Context, cl *http.Client, base string) (string, error) {
	v, err := get(ctx, cl, base+"/download/VERSION")
	if err != nil {
		return "", err
	}
	v = strings.TrimSpace(v)
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(base, "http")+"/ws?c=probe", &websocket.DialOptions{HTTPClient: cl})
	if err != nil {
		return v, fmt.Errorf("сигнализация: %v", err)
	}
	defer c.CloseNow()
	var m hub.Msg
	var hello struct{ ICE []hub.ICEServer }
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := wsjson.Read(rctx, c, &m); err != nil || m.Type != "hello" || json.Unmarshal(m.Data, &hello) != nil || len(hello.ICE) == 0 {
		return v, fmt.Errorf("сигнализация: нет hello с ICE (%v)", err)
	}
	c.Close(websocket.StatusNormalClosure, "")
	return v, nil
}

func sameVersion(v map[string]string) string {
	if len(slices.Compact(slices.Sorted(maps.Values(v)))) <= 1 {
		return ""
	}
	var l []string
	for _, h := range slices.Sorted(maps.Keys(v)) {
		l = append(l, h+" "+v[h])
	}
	return "разные версии: " + strings.Join(l, ", ")
}

// checkTURN — выделение адреса по UDP с учёткой, как у хаба (общий static-auth-secret).
func checkTURN(ctx context.Context, addr, secret string) error {
	ice := (&hub.Hub{TurnHosts: []string{"x"}, TurnSecret: secret}).ICEServers("probe")
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return err
	}
	defer pc.Close()
	c, err := turn.NewClient(&turn.ClientConfig{STUNServerAddr: addr, TURNServerAddr: addr, Username: ice[1].Username, Password: ice[1].Credential, Conn: pc})
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Listen(); err != nil {
		return err
	}
	actx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	relay, err := c.AllocateWithContext(actx)
	if err != nil {
		return fmt.Errorf("выделение адреса: %v", err)
	}
	return relay.Close()
}

// State — между запусками: сбои прошлого запуска (Seen), подтверждённые (Bad, о них уже сообщено), день сводки «жив».
type State struct {
	Seen  map[string]string `json:"seen"`
	Bad   map[string]string `json:"bad"`
	Alive string            `json:"alive"`
}

// Next — сообщение о переменах и новое состояние. Сбой подтверждён, если был и в прошлый запуск (одиночный
// таймаут сети не будит владельца); восстановление — сразу. Раз в сутки после 9:00 — «проба жива» (иначе
// молчание мёртвой пробы не отличить от «всё хорошо»).
func (s State) Next(bad map[string]string, now time.Time) (string, State) {
	n := State{Seen: bad, Bad: map[string]string{}, Alive: s.Alive}
	var down, up []string
	for k, e := range bad {
		if _, was := s.Bad[k]; was {
			n.Bad[k] = e
		} else if _, seen := s.Seen[k]; seen {
			n.Bad[k] = e
			down = append(down, k+": "+e)
		}
	}
	for k := range s.Bad {
		if _, still := bad[k]; !still {
			up = append(up, k)
		}
	}
	slices.Sort(down)
	slices.Sort(up)
	var msg []string
	if len(down) > 0 {
		msg = append(msg, "⚠️ AnyPC · сбой\n"+strings.Join(down, "\n"))
	}
	if len(up) > 0 {
		msg = append(msg, "✅ AnyPC · восстановлено: "+strings.Join(up, ", "))
	}
	if day := now.Format(time.DateOnly); now.Hour() >= 9 && s.Alive != day {
		n.Alive = day
		if len(msg) == 0 {
			msg = append(msg, fmt.Sprintf("✅ AnyPC · проба жива, сбоев сейчас: %d", len(n.Bad)))
		}
	}
	return strings.Join(msg, "\n\n"), n
}

func tg(ctx context.Context, cl *http.Client, token, chat, text string) error {
	if token == "" || chat == "" {
		return fmt.Errorf("нет TG_TOKEN/TG_CHAT")
	}
	r, _ := http.NewRequestWithContext(ctx, "POST", "https://api.telegram.org/bot"+token+"/sendMessage",
		strings.NewReader(url.Values{"chat_id": {chat}, "text": {text}, "disable_web_page_preview": {"true"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := cl.Do(r)
	if err != nil {
		return fmt.Errorf("%v", strings.ReplaceAll(err.Error(), token, "…")) // ошибка url содержит токен
	}
	defer resp.Body.Close()
	var ok struct {
		OK   bool   `json:"ok"`
		Desc string `json:"description"`
	}
	json.NewDecoder(resp.Body).Decode(&ok)
	if !ok.OK {
		return fmt.Errorf("%s", ok.Desc)
	}
	return nil
}
