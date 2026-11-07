package agent

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v5/vnet"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

// TestGCCLink — REQ-N-03 без root (вместо tc netem): хост шлёт 3 Мбит/с в канал 1 Мбит/с с очередью
// (виртуальная сеть pion, TBF), клиент — pion с TWCC-ответами по умолчанию, как браузер.
// Оценка GCC по задержке обязана упасть к полосе канала, а без неё (старый код) битрейт держался бы на 3 Мбит/с,
// пока очередь не начнёт терять.
func TestGCCLink(t *testing.T) {
	wan, err := vnet.NewRouter(&vnet.RouterConfig{CIDR: "10.0.0.0/24", LoggerFactory: logging.NewDefaultLoggerFactory()})
	if err != nil {
		t.Fatal(err)
	}
	hostNet, _ := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{"10.0.0.2"}})
	cliNet, _ := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{"10.0.0.3"}})
	q, _ := vnet.NewQueue(cliNet, vnet.NewTBFQueue(1_000_000, 15_000, 200_000)) // 1 Мбит/с к клиенту, буфер ~1.6 с
	if err := wan.AddNet(hostNet); err != nil {
		t.Fatal(err)
	}
	if err := wan.AddNet(q); err != nil {
		t.Fatal(err)
	}
	if err := wan.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close(); wan.Stop() })

	var hse, cse webrtc.SettingEngine
	hse.SetNet(hostNet)
	cse.SetNet(cliNet)
	api, bwe, err := newAPI(hse, 3000)
	if err != nil {
		t.Fatal(err)
	}
	host, _ := api.NewPeerConnection(webrtc.Configuration{})
	var est interface{ GetStats() map[string]any }
	select {
	case est = <-bwe:
	default:
		t.Fatal("оценщик GCC не создан")
	}
	capi, _, _ := newAPI(cse, 0)
	client, _ := capi.NewPeerConnection(webrtc.Configuration{})
	t.Cleanup(func() { host.Close(); client.Close() })

	track, _ := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000}, "video", "t")
	sender, _ := host.AddTrack(track)
	go func() {
		for {
			if _, _, err := sender.ReadRTCP(); err != nil {
				return
			}
		}
	}()
	client.OnTrack(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		for {
			if _, _, err := tr.ReadRTP(); err != nil {
				return
			}
		}
	})
	up := make(chan struct{})
	client.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateConnected {
			close(up)
		}
	})
	offer, _ := host.CreateOffer(nil)
	done := webrtc.GatheringCompletePromise(host)
	host.SetLocalDescription(offer)
	<-done
	if err := client.SetRemoteDescription(*host.LocalDescription()); err != nil {
		t.Fatal(err)
	}
	answer, _ := client.CreateAnswer(nil)
	done = webrtc.GatheringCompletePromise(client)
	client.SetLocalDescription(answer)
	<-done
	if err := host.SetRemoteDescription(*client.LocalDescription()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-up:
	case <-time.After(10 * time.Second):
		t.Fatal("нет соединения")
	}

	frame := make([]byte, 3_000_000/8/30) // 3 Мбит/с при 30 к/с
	tick := time.NewTicker(time.Second / 30)
	defer tick.Stop()
	end := time.After(12 * time.Second)
	for {
		select {
		case <-tick.C:
			rand.Read(frame)
			frame[0] = 0x41 // слайс H.264 (не IDR)
			if err := track.WriteSample(media.Sample{Data: frame, Duration: time.Second / 30}); err != nil {
				t.Fatal(err)
			}
		case <-end:
			got, _ := est.GetStats()["delayTargetBitrate"].(int) // её и берёт rate.report
			t.Logf("оценка GCC по задержке через 12 с: %d кбит/с (канал 1000, отправка 3000)", got/1000)
			if got > 1_300_000 || got < rateMin*1000 {
				t.Fatalf("оценка %d бит/с не сошлась к полосе канала 1 Мбит/с", got)
			}
			return
		}
	}
}
