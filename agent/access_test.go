package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"anypc/pake"

	"github.com/pion/webrtc/v4"
)

// TestIndependentAccess — оба профиля на одном хосте: старый клиент выбирает основной one-time CPace и входит без
// Confirm/TOTP, а SpaceJoin выбирает psalt/pmsg, проходит TOTP и не наследует одноразовый ViewOnly.
func TestIndependentAccess(t *testing.T) {
	url := local(t)
	oneSalt := []byte("one-time-0123456")
	var confirm, otpCalls, trustCalls atomic.Int32
	var shut atomic.Bool
	used := make(chan struct{}, 2)
	r := spaceHost(t, url, "123456789", func(r *spaceRig) {
		r.a.OneTimeSecret = func() ([]byte, []byte) { return oneSalt, pake.KDF("one-time-code", oneSalt) }
		r.a.Confirm = func(string, string) Answer { confirm.Add(1); return Deny }
		otp := r.a.OTP
		r.a.OTP = func(user, code string) (bool, bool) { otpCalls.Add(1); return otp(user, code) }
		r.a.LoginShut = func(string) bool { return shut.Load() }
		r.a.ViewOnly = func() bool { return true }
		r.a.CodeUsed = func() { used <- struct{}{} }
		r.a.Trusted = func([]byte, string) bool { trustCalls.Add(1); return false }
		r.a.Trust = func([]byte, string, []byte) { trustCalls.Add(1) }
		r.a.KeyTrust = func([]byte, string, []byte) { trustCalls.Add(1) }
	})
	shut.Store(true) // одноразовый вход не зависит от сверки permanent-пространства
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	first, ok, err := dialOneTimeAccess(ctx, url, "123456789", "one-time-code", newKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Salt, oneSalt) || len(first.Msg) == 0 || !bytes.Equal(first.PermSalt, salt) || len(first.PermMsg) == 0 {
		t.Fatalf("первый a не содержит оба независимых CPace: %+v", first)
	}
	if !ok.View || !ok.Mode || ok.Trust || ok.Pass || ok.Key {
		t.Fatalf("неожиданные права one-time ok: %+v", ok)
	}
	if confirm.Load() != 0 || otpCalls.Load() != 0 || trustCalls.Load() != 0 {
		t.Fatalf("one-time вызвал permanent-проверки: Confirm=%d OTP=%d trust=%d", confirm.Load(), otpCalls.Load(), trustCalls.Load())
	}
	select {
	case <-used:
	case <-time.After(5 * time.Second):
		t.Fatal("завершённая one-time сессия не израсходовала код")
	}

	shut.Store(false)
	out, err := SpaceJoin(ctx, SpaceDial{Server: url, ID: "123456789", Key: newKey(), Password: "secret123", Code: r.owner.code(),
		Sign: func(m []byte, _ ed25519.PublicKey, _ ...[]byte) ([]byte, error) {
			return append(bytes.Clone(m), "+N"...), nil
		}})
	if err != nil {
		t.Fatalf("permanent с OTP и включённым one-time ViewOnly: %v", err)
	}
	if string(out) != "M-SECRET-MARK-1+N" || otpCalls.Load() == 0 || confirm.Load() != 0 {
		t.Fatalf("permanent: out=%q OTP=%d Confirm=%d", out, otpCalls.Load(), confirm.Load())
	}
	waitAccessRelease(t, r.a)
	select {
	case <-used:
		t.Fatal("permanent сессия израсходовала одноразовый код")
	default:
	}

	// Когда ViewOnly выключен, возврат из просмотра в управление не требует ConfirmControl.
	s := &session{cid: "one-time"}
	s.once.Store(true)
	s.byAsk.Store(true)
	s.view.Store(true)
	r.a.ViewOnly = func() bool { return false }
	r.a.ConfirmControl = func(string, string) bool { t.Fatal("one-time спросил ConfirmControl"); return false }
	view := false
	r.a.setMode(context.Background(), s, &view, func(m modeMsg) {
		if !m.OK || m.View {
			t.Errorf("возврат управления one-time: %+v", m)
		}
	})
}

func waitAccessRelease(t *testing.T, a *Agent) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.mu.Lock()
		busy := a.sess != nil
		a.mu.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("permanent сессия не завершилась")
		}
		time.Sleep(time.Millisecond)
	}
}

// dialOneTimeAccess — старый клиент без permanent: основной a, обычный b; Trust/Pass нарочно запрошены, чтобы
// проверить, что новый одноразовый путь их не выдаёт. Возвращает первый a и ok.
func dialOneTimeAccess(ctx context.Context, server, id, code string, key ed25519.PrivateKey) (first, ok authMsg, err error) {
	err = hostDial(ctx, server, id, connectReq{}, func(pc *webrtc.PeerConnection, finish func(error)) {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			if dc.Label() != "auth" {
				return
			}
			var want []byte
			dc.OnMessage(func(msg webrtc.DataChannelMessage) {
				var am authMsg
				if json.Unmarshal(msg.Data, &am) != nil {
					return
				}
				switch am.T {
				case "a":
					first = am
					fc, fh := pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP)
					b, conf, hc, e := pake.ClientRespond(code, am.Salt, am.Msg, id, fc, fh)
					if e != nil {
						finish(e)
						return
					}
					want = hc
					cpub, csig, e := signB(key, id, pc)
					if e != nil {
						finish(e)
						return
					}
					out, _ := json.Marshal(authMsg{T: "b", Msg: b, Conf: conf, CPub: cpub, CSig: csig, Trust: true, Pass: true})
					dc.SendText(string(out))
				case "ok":
					fc, fh := pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP)
					if !bytes.Equal(am.Conf, want) || pake.HostVerify(am.Pub, am.Sig, id, fc, fh) != nil {
						finish(fmt.Errorf("недействительный ok"))
						return
					}
					ok = am
					finish(nil)
				case "ask", "otp":
					finish(fmt.Errorf("one-time потребовал %s", am.T))
				case "fail", "denied", "locked", "busy":
					finish(fmt.Errorf("one-time отказ: %s %s", am.T, am.Why))
				}
			})
		})
	})
	return first, ok, err
}
