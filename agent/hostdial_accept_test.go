package agent

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/webrtc/v4"
)

// приёмка Ч12: обмен после установленного соединения переживает spaceLinkWait (превью ждёт человека до 2 мин,
// файл идёт минутами) — срок соединения не должен рвать уже соединённый обмен.
func TestHostDialLinkedOutlivesLinkWait(t *testing.T) {
	linkWait(t, time.Second)
	url := fakeHostHub(t, true, func(*webrtc.PeerConnection, *webrtc.DataChannel) {})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	t0 := time.Now()
	err := hostDial(ctx, url, "123456789", connectReq{View: true}, func(pc *webrtc.PeerConnection, finish func(error)) {
		pc.OnDataChannel(func(*webrtc.DataChannel) { time.AfterFunc(3*time.Second, func() { finish(nil) }) })
	})
	if err != nil || time.Since(t0) < 3*time.Second {
		t.Fatalf("соединённый обмен дольше spaceLinkWait: %v за %v", err, time.Since(t0))
	}
}

// приёмка Ч12: STUN отвечает (srflx собран), а хост недостижим — это nolink, а не noudp: брандмауэр этого ПК ни при чём.
func TestHostDialNoLinkWithSTUN(t *testing.T) {
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			m := &stun.Message{Raw: append([]byte{}, buf[:n]...)}
			if m.Decode() != nil || m.Type != stun.BindingRequest {
				continue
			}
			u := from.(*net.UDPAddr)
			res, err := stun.Build(stun.NewTransactionIDSetter(m.TransactionID), stun.BindingSuccess,
				&stun.XORMappedAddress{IP: net.IPv4(203, 0, 113, 7), Port: u.Port}, stun.Fingerprint)
			if err == nil {
				c.WriteTo(res.Raw, from)
			}
		}
	}()
	linkWait(t, 2*time.Second)
	old := fakeHello
	fakeHello = `{"ICE":[{"urls":["stun:` + c.LocalAddr().String() + `"]}]}`
	t.Cleanup(func() { fakeHello = old })
	url := fakeHostHub(t, false, func(*webrtc.PeerConnection, *webrtc.DataChannel) {})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = hostDial(ctx, url, "123456789", connectReq{View: true}, func(*webrtc.PeerConnection, func(error)) {})
	if !errors.Is(err, ErrSpaceNoLink) || errors.Is(err, ErrSpaceNoUDP) {
		t.Fatalf("STUN доступен, хост недостижим: %v — ждали nolink без noudp", err)
	}
}
