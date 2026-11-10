package conn

import (
	"net"
	"testing"

	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"golang.org/x/net/ipv6"
)

// recordingReplyPather is a StatefulReplyPather that records the end-to-end options of every
// packet handed to SetState.
type recordingReplyPather struct {
	options [][]*slayers.EndToEndOption
}

func (p *recordingReplyPather) SetState(_ snet.SourceIdentifier, pkt snet.Packet) error {
	p.options = append(p.options, pkt.E2eExtnContents)
	return nil
}

func (p *recordingReplyPather) ReplyPathTo(
	_ snet.SourceIdentifier, rpath snet.RawPath) (snet.DataplanePath, error) {
	return p.ReplyPath(rpath)
}

func (p *recordingReplyPather) ReplyPath(snet.RawPath) (snet.DataplanePath, error) {
	return snetpath.Empty{}, nil
}

// TestProcessMessageForgetsPreviousExtension checks that a packet without an end-to-end
// extension is not given the reverse-reservation option of a packet received before it in
// the same (pooled) slot. Seen on SCIERA: after each Hummingbird handover the receiver kept
// handing a stale option, pointing into a reused receive buffer, to the reply pather.
func TestProcessMessageForgetsPreviousExtension(t *testing.T) {
	pather := &recordingReplyPather{}
	s := &ScionBatchConn{
		pathManager: newTestPathManager(t, nil),
		replyPather: pather,
		logger:      nopLogger{},
	}

	withExtn := extnTestPacket(snetpath.Empty{}, []byte("handover packet"))
	revExtn := &slayers.EndToEndExtn{Options: []*slayers.EndToEndOption{
		{OptType: slayers.OptTypeReversePath, OptData: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
	}}
	if err := Serialize(withExtn, nil, revExtn); err != nil {
		t.Fatalf("Serialize with extension: %v", err)
	}
	plain := extnTestPacket(snetpath.Empty{}, []byte("an ordinary packet that follows"))
	if err := Serialize(plain, nil, nil); err != nil {
		t.Fatalf("Serialize without extension: %v", err)
	}

	// One receive buffer and one decode slot, both reused, as in ReadBatch.
	rxBuf := make([]byte, 2000)
	msg := ipv6.Message{
		Buffers: [][]byte{rxBuf},
		Addr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 30001},
	}
	var slot snet.Packet
	receive := func(raw []byte) {
		t.Helper()
		msg.N = copy(rxBuf, raw)
		buf := make([]byte, 2000)
		var size int
		var ep Endpoint
		if !s.processMessage(&msg, &slot, nil, buf, &size, &ep) {
			t.Fatalf("processMessage rejected the packet")
		}
	}

	receive(withExtn.Bytes)
	receive(plain.Bytes)

	if len(pather.options) != 2 {
		t.Fatalf("SetState called %d times, want 2", len(pather.options))
	}
	if got := pather.options[0]; len(got) != 1 || got[0].OptType != slayers.OptTypeReversePath {
		t.Errorf("first packet: options %v, want the reverse-path option", got)
	}
	if got := pather.options[1]; len(got) != 0 {
		t.Errorf("second packet has no extension, but SetState got %d option(s): %v",
			len(got), got)
	}
}
