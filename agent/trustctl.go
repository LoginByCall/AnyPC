package agent

// Ч7б, решение владельца B (TZ.md §16, 2026-11-15): «Добавить в моё пространство» без переподключения — ключ клиента
// во вход без пароля (REQ-S-24) из уже вошедшей сессии, ctl "trust". Условия — те же, что у trust в "b" (agent.go):
// вход паролем записи (не ключом, не пропуском, не через «Разрешить»/код разовой помощи) с кодом TOTP, ключ клиента
// доказан подписью над DTLS-отпечатками ЭТОГО соединения в "b" (s.cpub — новое доказательство не принимается, новых
// примитивов нет), режим не «Спрашивать». Ключ добавляет тот же KeyTrust (те же пределы числа ключей, та же строка
// журнала «ключ … добавлен»). Один раз за сессию.
// ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md A13: ключевой материал, вход без пароля).
//
// Совместимость — только добавления: хост объявляет trust:true в "ok" сессии, которой это можно; старый хост поля не
// шлёт (и неизвестный t в ctl пропускает) — клиент идёт прежним путём (повторный вход с trust в "b"); старый клиент
// "trust" в ctl не шлёт.

import (
	"bytes"
	"encoding/json"
	"log"

	"anypc/pake"
)

// trustMsg — канал "ctl". Клиент → {"t":"trust"} (необязательно "cpub" — какой ключ клиент считает своим: не тот, что
// доказан в "b", — отказ); хост → {"t":"trust","ok":true,"fp":"…"} (fp — pake.KeyFingerprint добавленного ключа) |
// {"t":"trust","why":"…"}: "rights" — сессия вошла не паролем и кодом TOTP (ключом, пропуском, через «Разрешить», без
// TOTP) или у хоста нет входа по ключу; "key" — ключ не доказан в "b" этого соединения или cpub не тот; "again" — уже
// был trust в этой сессии (ctl или "b"); "ask" — сейчас режим «Спрашивать» или у записи нет TOTP; "gone" — запись
// удалили, сменили ей пароль, ключ исключён из пространства, или ключ не добавился.
type trustMsg struct {
	T    string `json:"t"`
	CPub []byte `json:"cpub,omitempty"`
	OK   bool   `json:"ok,omitempty"`
	FP   string `json:"fp,omitempty"`
	Why  string `json:"why,omitempty"`
}

// trustCan — объявить trust в "ok": сессия вошла паролем и кодом, ключ доказан в "b", trust ещё не было.
func (a *Agent) trustCan(s *session) bool {
	s.mu.Lock()
	kp, cpub := s.keyPin, s.cpub
	s.mu.Unlock()
	return s.trustOK.Load() && cpub != nil && kp == nil && !s.trusted.Load() && a.KeyLogin != nil && a.KeyTrust != nil
}

// trustCtl — хост: ответ на ctl "trust" вошедшей сессии.
func (a *Agent) trustCtl(s *session, data []byte, reply func(trustMsg)) {
	var m trustMsg
	if json.Unmarshal(data, &m) != nil {
		return
	}
	// отказ до «одного на сессию» — без журнала (поток отказов его не засорит); после — единственная попытка, в журнал
	no := func(why string) { reply(trustMsg{T: "trust", Why: why}) }
	noLog := func(why string) {
		log.Printf("сессия %s: «Добавить» в сессии — отказ (%s)", s.label(), why)
		no(why)
	}
	s.mu.Lock()
	user, salt, cpub, kp := s.user, s.salt, s.cpub, s.keyPin
	s.mu.Unlock()
	switch {
	case !s.trustOK.Load() || a.KeyLogin == nil || a.KeyTrust == nil:
		no("rights")
		return
	case cpub == nil || m.CPub != nil && !bytes.Equal(m.CPub, cpub):
		no("key")
		return
	case kp != nil || !s.trusted.CompareAndSwap(false, true): // trust уже был в "b" (ключ добавлен там) или в ctl
		no("again")
		return
	}
	// режим могли сменить за время сессии: как в "b" — без подтверждения и с TOTP записи
	unattended := a.Confirm == nil || a.Unattended != nil && a.Unattended()
	otpSet := false
	if unattended && a.OTP != nil {
		otpSet, _ = a.OTP(user, "")
	}
	if !otpSet {
		noLog("ask")
		return
	}
	if gone, _ := a.revoked(s); gone { // как accept перед KeyTrust: запись, пароль, исключение ключа из пространства
		noLog("gone")
		return
	}
	a.KeyTrust(cpub, user, salt) // тот же путь, что trust в "b": соль та же — добавит (в журнал пишет сам)
	if in, on := a.KeyLogin(cpub, user); !in || !on {
		noLog("gone")
		return
	}
	fp := pake.KeyFingerprint(cpub)
	log.Printf("сессия %s: «Добавить» в сессии — ключ %s во входе без пароля", s.label(), fp[:9])
	reply(trustMsg{T: "trust", OK: true, FP: fp})
}
