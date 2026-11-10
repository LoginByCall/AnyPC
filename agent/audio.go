package agent

import (
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

// Звук (PLAN.md, REQ-F-21/22, маршрут B): Go-хост только пересылает SDP между клиентом (канал ctl) и окном хоста
// (hostInfo / audioAnswer). Сам звук идёт вторым RTCPeerConnection между страницами, микрофоны — их getUserMedia.

// audioWait — сколько ждать ответа окна хоста (оно опрашивает hostInfo раз в секунду); дольше — окно закрыто.
var audioWait = 5 * time.Second

type audioState struct {
	mu    sync.Mutex
	offer string // предложение клиента, окно хоста ещё не ответило
	seq   int    // номер предложения: таймер старого не отвечает «closed» на новое
	mic   bool   // REQ-F-22: микрофон окна хоста включён
}

// audioOffer — клиент прислал предложение: отдать окну хоста; не ответило за audioWait → клиенту «closed».
func (s *session) audioOffer(sdp string) {
	s.audio.mu.Lock()
	s.audio.offer = sdp
	s.audio.seq++
	seq := s.audio.seq
	s.audio.mu.Unlock()
	time.AfterFunc(audioWait, func() {
		s.audio.mu.Lock()
		stale := s.audio.seq != seq || s.audio.offer == ""
		s.audio.offer = ""
		s.audio.mu.Unlock()
		if !stale {
			s.sendCtl(ctlMsg{T: "audio", Err: "closed"})
		}
	})
}

func (s *session) sendCtl(m ctlMsg) {
	if s.ctl == nil {
		return
	}
	b, _ := json.Marshal(m)
	s.ctl.SendText(string(b))
}

// AudioPending — для окна хоста: предложение звука текущей сессии ("" — нет).
func (a *Agent) AudioPending() (cid, sdp string) {
	a.mu.Lock()
	s := a.sess
	a.mu.Unlock()
	if s == nil || !s.authed.Load() {
		return "", ""
	}
	s.audio.mu.Lock()
	defer s.audio.mu.Unlock()
	return s.cid, s.audio.offer
}

// AudioICE — STUN/TURN хаба для второго соединения окна хоста (те же, что у сессии).
func (a *Agent) AudioICE() []webrtc.ICEServer {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.ice)
}

// AudioAnswer — ответ окна хоста на предложение сессии cid.
func (a *Agent) AudioAnswer(cid, sdp string) error {
	s := a.byCID(cid)
	if s == nil {
		return errors.New("сессии нет")
	}
	s.audio.mu.Lock()
	had := s.audio.offer != ""
	s.audio.offer = ""
	s.audio.mu.Unlock()
	if !had {
		return errors.New("предложения нет или оно устарело")
	}
	s.sendCtl(ctlMsg{T: "audio", SDP: sdp})
	return nil
}

// AudioMic — окно хоста включило или выключило свой микрофон (REQ-F-22: это видно на плашке).
// TODO(REQ-F-22): плашка пока не показывает 🎤 — до этого звук не выпускать.
func (a *Agent) AudioMic(on bool) {
	a.mu.Lock()
	s := a.sess
	a.mu.Unlock()
	if s != nil {
		s.audio.mu.Lock()
		s.audio.mic = on
		s.audio.mu.Unlock()
	}
}
