package conn

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

// extnPath is an empty path that carries an end-to-end extension, the way snet's
// own serializer learns about one (DataplanePacketExtender).
type extnPath struct {
	snetpath.Empty
	extn *slayers.EndToEndExtn
}

func (p extnPath) EndToEndExtn() (*slayers.EndToEndExtn, error) {
	extn := *p.extn // snet sets NextHdr on what it gets: keep the test's copy pristine
	return &extn, nil
}

func testExtn() *slayers.EndToEndExtn {
	return &slayers.EndToEndExtn{Options: []*slayers.EndToEndOption{
		{OptType: 253, OptData: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
	}}
}

func extnTestPacket(path snet.DataplanePath, payload []byte) *snet.Packet {
	return &snet.Packet{
		Bytes: make(snet.Bytes, 2000),
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{IA: addr.MustParseIA("1-ff00:0:110"),
				Host: addr.HostIP(netip.MustParseAddr("127.0.0.1"))},
			Destination: snet.SCIONAddress{IA: addr.MustParseIA("1-ff00:0:110"),
				Host: addr.HostIP(netip.MustParseAddr("127.0.0.2"))},
			Path:    path,
			Payload: snet.UDPPayload{SrcPort: 32000, DstPort: 32001, Payload: payload},
		},
	}
}

// decodeExtnPacket decodes a SCION/E2E/UDP packet, failing the test unless all three are there.
func decodeExtnPacket(t *testing.T, raw []byte) (slayers.SCION, slayers.EndToEndExtn, slayers.UDP) {
	t.Helper()
	var scn slayers.SCION
	var e2e slayers.EndToEndExtn
	var udp slayers.UDP
	parser := gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION, &scn, &e2e, &udp)
	parser.IgnoreUnsupported = true // the UDP payload has no decoder
	decoded := []gopacket.LayerType{}
	if err := parser.DecodeLayers(raw, &decoded); err != nil {
		t.Fatalf("decoding %x: %v (decoded %v)", raw, err, decoded)
	}
	if len(decoded) != 3 {
		t.Fatalf("want SCION, E2E and UDP layers, decoded %v", decoded)
	}
	return scn, e2e, udp
}

// TestSerializeEndToEndExtnLikeSnet checks that a packet carrying the reverse-reservation
// extension is laid out as snet lays it out: the SCION header names the extension, the
// extension names UDP, and the bytes are the same apart from the flow ID and the UDP
// checksum, which Serialize computes differently on purpose.
func TestSerializeEndToEndExtnLikeSnet(t *testing.T) {
	payload := []byte("a WireGuard message")

	want := extnTestPacket(extnPath{extn: testExtn()}, payload)
	if err := want.Serialize(); err != nil {
		t.Fatalf("snet serialization: %v", err)
	}

	revExtn := testExtn()
	got := extnTestPacket(snetpath.Empty{}, payload)
	if err := Serialize(got, nil, revExtn); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if revExtn.NextHdr != 0 {
		t.Errorf("Serialize changed the caller's extension: NextHdr %v", revExtn.NextHdr)
	}

	scn, e2e, udp := decodeExtnPacket(t, got.Bytes)
	if scn.NextHdr != slayers.End2EndClass {
		t.Errorf("SCION next header %v, want %v", scn.NextHdr, slayers.End2EndClass)
	}
	if e2e.NextHdr != slayers.L4UDP {
		t.Errorf("extension next header %v, want %v (UDP)", e2e.NextHdr, slayers.L4UDP)
	}
	if udp.DstPort != 32001 || !bytes.Equal(udp.Payload, payload) {
		t.Errorf("UDP behind the extension: port %d, payload %q", udp.DstPort, udp.Payload)
	}

	if len(got.Bytes) != len(want.Bytes) {
		t.Fatalf("length %d, snet's %d\n got %x\nwant %x", len(got.Bytes), len(want.Bytes),
			got.Bytes, want.Bytes)
	}
	// Mask what is meant to differ: the flow ID (low 20 bits of the first word) and the
	// UDP checksum (bytes 6-7 of the UDP header, which ends the packet's headers).
	normalize := func(raw []byte) []byte {
		out := append([]byte(nil), raw...)
		out[1] &= 0xf0
		out[2], out[3] = 0, 0
		udpOff := len(out) - len(payload) - UDPHeaderLen
		out[udpOff+6], out[udpOff+7] = 0, 0
		return out
	}
	if g, w := normalize(got.Bytes), normalize(want.Bytes); !bytes.Equal(g, w) {
		t.Errorf("bytes differ from snet's\n got %x\nwant %x", g, w)
	}
}

// TestSerializeBatchEndToEndExtn checks that every packet of a batch carries the
// extension with UDP as its next header, not only the template packet.
func TestSerializeBatchEndToEndExtn(t *testing.T) {
	pkts := []snet.Packet{
		*extnTestPacket(snetpath.Empty{}, []byte("first")),
		*extnTestPacket(snetpath.Empty{}, []byte("second, longer")),
	}
	bufs := make([][]byte, len(pkts))
	if err := SerializeBatch(pkts, bufs, nil, testExtn()); err != nil {
		t.Fatalf("SerializeBatch: %v", err)
	}
	for i, raw := range bufs {
		_, e2e, udp := decodeExtnPacket(t, raw)
		if e2e.NextHdr != slayers.L4UDP {
			t.Errorf("packet %d: extension next header %v, want UDP", i, e2e.NextHdr)
		}
		if want := pkts[i].Payload.(snet.UDPPayload).Payload; !bytes.Equal(udp.Payload, want) {
			t.Errorf("packet %d: payload %q, want %q", i, udp.Payload, want)
		}
	}
}
