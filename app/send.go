package main

// Ч10.3 «Отправить» — API окна и трея (UI-REDESIGN.md, «Ч10 «Отправить»»; экран и подменю трея — Ч10.5). Одни и те же
// имена (sendNames) — в api() (Linux, Мак: POST /api/<имя> с X-Token) и в w.Bind (Windows), как у пространства
// (spaceapi.go). Отправка идёт в фоне (одна за раз), окно опрашивает sendState или hostInfo.send, трей подписывается
// sendOps.watch. Ошибки окну — только коды send:<код>. В журнал — одна строка на отправку, без путей и текста.
//
// Кому (sendDial): ID из состава M этого ПК — свой ПК (ключ члена, без кода); иначе чужой — с разовым кодом с его
// экрана (ключ того ПК после верного кода запоминается в known, как после входа) или без кода по ключу из known
// (тот ПК должен был закрепить этот ПК раньше — иначе send:nokey). ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (A13): выбор доказательства.

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"sync"

	"anypc/agent"
	"anypc/hub"
	"anypc/pake"
)

var sendNames = []string{"sendStart", "sendState", "sendCancel", "sendClear", "sendTargets"}

var (
	errSendRunning = errors.New("отправка: уже идёт другая")
	errSendNoOp    = errors.New("отправка: отменять нечего")
	errSendID      = errors.New("отправка: неверный ID")
	errSendSelf    = errors.New("отправка: это этот ПК")
	errSendBoth    = errors.New("отправка: текст или буфер обмена — что-то одно")
	errSendArgs    = errors.New("отправка: неверный запрос")
)

// sendReq — sendStart окна: кому (id, code — разовый код чужого ПК) и что.
type sendReq struct {
	ID    string   `json:"id"`
	Code  string   `json:"code"`
	Files []string `json:"files"`
	Dirs  []string `json:"dirs"`
	Text  string   `json:"text"`
	Clip  bool     `json:"clip"`
}

// sendCodes — ошибка → код окна (первое совпадение по errors.Is).
var sendCodes = []struct {
	err  error
	code string
}{
	{errSendRunning, "running"}, {errSendNoOp, "noop"}, {errSendID, "id"}, {errSendSelf, "self"}, {errSendBoth, "both"},
	{errSendArgs, "args"}, {agent.ErrSendEmpty, "empty"}, {agent.ErrSendClip, "clip"}, {agent.ErrSendNotFile, "notfile"},
	{agent.ErrSendMany, "many"}, {agent.ErrRecvOld, "old"}, {agent.ErrRecvOldDirs, "olddirs"}, {agent.ErrRecvCode, "code"},
	{agent.ErrRecvLocked, "locked"}, {agent.ErrRecvNoKey, "nokey"}, {agent.ErrRecvNoCode, "nocode"},
	{agent.ErrRecvDenied, "denied"}, {agent.ErrRecvBusy, "busy"}, {agent.ErrRecvRate, "rate"}, {agent.ErrRecvLimit, "limit"},
	{agent.ErrRecvGone, "gone"}, {agent.ErrRecvViewOnly, "viewonly"}, {agent.ErrRecvWait, "wait"},
	{agent.ErrRecvKnown, "known"}, {agent.ErrRecvPath, "path"}, {agent.ErrSpaceHostKey, "hostkey"},
	{agent.ErrSpaceIDKey, "badid"}, {agent.ErrSpaceSkew, "clock"}, {agent.ErrSpaceOffline, "offline"},
	{agent.ErrSpaceRefused, "refused"}, {fs.ErrNotExist, "nofile"}, {fs.ErrPermission, "perm"},
	{context.Canceled, "cancel"}, {context.DeadlineExceeded, "timeout"},
}

// sendErrCode — код ошибки для окна; отказ получателя без своего кода выше (место, ввод-вывод, буфер) — rx_<код>.
func sendErrCode(err error) string {
	for _, x := range sendCodes {
		if errors.Is(err, x.err) {
			return x.code
		}
	}
	var re *agent.RecvError
	if errors.As(err, &re) && (re.Code == "disk" || re.Code == "io" || re.Code == "clip") {
		return "rx_" + re.Code
	}
	return "other"
}

// sendRun — отправка (подмена — в тестах).
var sendRun = agent.SendTo

// sendOpState — отправка для окна: kind — own | code | known.
type sendOpState struct {
	id, kind string
	state    string // run | done | err
	prog     agent.SendProgress
	res      agent.SendResult
	err      error
	cancel   context.CancelFunc
}

type sendOpRun struct {
	mu      sync.Mutex
	cur     *sendOpState
	watches []func(map[string]any)
	wg      sync.WaitGroup // тест: дождаться конца
}

var sendOps sendOpRun

// watch — трей (Ч10.5): f зовётся с тем же, что sendState, при начале, смене файла и конце (не на каждом куске).
func (r *sendOpRun) watch(f func(map[string]any)) {
	r.mu.Lock()
	r.watches = append(r.watches, f)
	r.mu.Unlock()
}

func (r *sendOpRun) notify() {
	r.mu.Lock()
	ws, m := append([]func(map[string]any){}, r.watches...), r.snapLocked()
	r.mu.Unlock()
	for _, f := range ws {
		f(m)
	}
}

// sendDial — кому и как доказывать (см. начало файла).
func sendDial(c *config, q sendReq) (agent.SendDial, string, error) {
	if !hub.IsHostID(q.ID) {
		return agent.SendDial{}, "", errSendID
	}
	if q.Clip && q.Text != "" {
		return agent.SendDial{}, "", errSendBoth
	}
	if len(q.Files)+len(q.Dirs) == 0 && q.Text == "" && !q.Clip {
		return agent.SendDial{}, "", agent.ErrSendEmpty
	}
	name, _ := os.Hostname()
	c.mu.Lock()
	c.reload()
	d := agent.SendDial{Server: c.Server, ID: q.ID, Key: append([]byte(nil), c.Key...), From: c.ID, Name: name,
		Files: q.Files, Dirs: q.Dirs, Text: q.Text, Clip: q.Clip}
	self := c.ID
	if m := c.spaceLocked(); m != nil {
		for _, x := range m.Members {
			if x.ID == q.ID {
				d.HostPub = append([]byte(nil), x.Pub...)
			}
		}
	}
	d.Known = c.Known[q.ID]
	c.mu.Unlock()
	switch {
	case q.ID == self:
		return d, "", errSendSelf
	case d.HostPub != nil:
		d.Known = "" // свой ПК — ключ из M
		return d, "own", nil
	case q.Code != "":
		d.Code = q.Code
		return d, "code", nil
	case d.Known == "":
		return d, "", agent.ErrRecvKnown
	}
	return d, "known", nil
}

// start — отправка в фоне; идёт другая — errSendRunning; кончившаяся заменяется.
func (r *sendOpRun) start(c *config, q sendReq) error {
	d, kind, err := sendDial(c, q)
	if err != nil {
		return err
	}
	r.mu.Lock()
	if r.cur != nil && r.cur.state == "run" {
		r.mu.Unlock()
		return errSendRunning
	}
	ctx, cancel := context.WithCancel(context.Background())
	o := &sendOpState{id: q.ID, kind: kind, state: "run", cancel: cancel}
	r.cur = o
	r.mu.Unlock()
	item := 0
	d.Progress = func(p agent.SendProgress) {
		r.mu.Lock()
		o.prog = p
		r.mu.Unlock()
		if p.Item != item {
			item = p.Item
			r.notify()
		}
	}
	r.notify()
	r.wg.Go(func() {
		defer cancel()
		res, err := sendRun(ctx, d)
		if err == nil && kind == "code" && c.knownGet(d.ID) == "" && len(res.HostPub) > 0 { // ключ доказан и кодом
			c.knownSet(d.ID, pake.KeyFingerprint(res.HostPub))
		}
		r.mu.Lock()
		o.res, o.err, o.state = res, err, "done"
		if err != nil {
			o.state = "err"
		}
		r.mu.Unlock()
		if err != nil {
			log.Printf("отправка на %s: ошибка %s", d.ID, sendErrCode(err)) // только код: в тексте ошибок ОС — пути
		} else {
			log.Printf("отправка на %s: файлов %d, %d байт%s", d.ID, res.Files, res.Bytes, map[bool]string{true: ", текст"}[res.Text])
		}
		r.notify()
	})
	return nil
}

// stop — отменить идущую; нет — errSendNoOp.
func (r *sendOpRun) stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur == nil || r.cur.state != "run" {
		return errSendNoOp
	}
	r.cur.cancel()
	return nil
}

// clear — стереть итог; идёт — errSendRunning.
func (r *sendOpRun) clear() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur != nil && r.cur.state == "run" {
		return errSendRunning
	}
	r.cur = nil
	return nil
}

func (r *sendOpRun) snap() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.snapLocked()
}

// snapLocked — состояние для окна и трея: nil — отправки нет. skipped — до 20 путей в папках, что не ушли (ссылки,
// устройства, негодные имена), skippedN — сколько всего.
func (r *sendOpRun) snapLocked() map[string]any {
	o := r.cur
	if o == nil {
		return nil
	}
	m := map[string]any{"id": o.id, "kind": o.kind, "state": o.state, "item": o.prog.Item, "items": o.prog.Items,
		"done": o.prog.Done, "total": o.prog.Total}
	if o.err != nil {
		m["err"] = sendErrCode(o.err)
	}
	if o.state == "done" {
		m["files"], m["bytes"], m["text"] = o.res.Files, o.res.Bytes, o.res.Text
	}
	if o.state != "run" {
		sk := o.res.Skipped
		m["skippedN"] = len(sk)
		m["skipped"] = append([]string{}, sk[:min(len(sk), 20)]...)
	}
	return m
}

// sendTargets — кому можно без кода: свои ПК из M (кроме этого) и ПК с запомненным ключом (known; примут ли они
// без кода, решает их закрепление).
func sendTargets(c *config) map[string]any {
	c.mu.Lock()
	c.reload()
	m := c.spaceLocked()
	self := c.ID
	own, known := []map[string]string{}, []map[string]string{}
	in := map[string]bool{}
	if m != nil {
		for _, x := range m.Members {
			in[x.ID] = true
			if x.ID != self {
				own = append(own, map[string]string{"id": x.ID, "fp": pake.KeyFingerprint(x.Pub)})
			}
		}
	}
	for id, fp := range c.Known {
		if !in[id] && id != self {
			known = append(known, map[string]string{"id": id, "fp": fp})
		}
	}
	c.mu.Unlock()
	return map[string]any{"own": own, "known": known}
}

// sendCall — вызов окна name (из sendNames); ошибка — только send:<код>.
func sendCall(c *config, name string, args []json.RawMessage) (any, error) {
	var res any
	var err error
	switch name {
	case "sendStart":
		var q sendReq
		if len(args) < 1 || json.Unmarshal(args[0], &q) != nil {
			err = errSendArgs
		} else {
			err = sendOps.start(c, q)
		}
	case "sendState":
		res = sendOps.snap()
	case "sendCancel":
		err = sendOps.stop()
	case "sendClear":
		err = sendOps.clear()
	case "sendTargets":
		res = sendTargets(c)
	default:
		err = errSendArgs
	}
	if err != nil {
		return nil, errors.New("send:" + sendErrCode(err))
	}
	return res, nil
}
