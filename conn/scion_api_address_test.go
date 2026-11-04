package conn

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/hummingbird/marketplace"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func newAPIPathManager(address string) (*PathManager, error) {
	return NewPathManager(&fakeDaemon{}, addr.MustParseIA("1-ff00:0:110"), PathPolicyFirst,
		nopLogger{}, WithRefreshInterval(time.Hour), WithAPIAddress(address))
}

func getMetrics(t *testing.T, address string) {
	t.Helper()
	resp, err := http.Get("http://" + address + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics on %s: %s", address, resp.Status)
	}
}

func TestParseAPIAddress(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:28016", "[::1]:28016", ":28016", "localhost:1"} {
		if err := ParseAPIAddress(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"28016", "127.0.0.1", "127.0.0.1:", ":0", ":65536", ":abc", "::1:28016"} {
		if err := ParseAPIAddress(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLoadScionConfigAPIAddress(t *testing.T) {
	t.Setenv(EnvSCIONLocalIA, "1-ff00:0:110,127.0.0.1")
	cfg, err := LoadScionConfigFromEnv()
	if err != nil {
		t.Skipf("no SCION configuration available: %v", err)
	}
	if cfg.APIAddress != "" {
		t.Errorf("unset variable gave %q", cfg.APIAddress)
	}
	t.Setenv(EnvSCIONPathAPIAddress, "127.0.0.1:28016")
	if cfg, err = LoadScionConfigFromEnv(); err != nil || cfg.APIAddress != "127.0.0.1:28016" {
		t.Errorf("got %v, %v", cfg, err)
	}
	t.Setenv(EnvSCIONPathAPIAddress, "28016")
	if _, err = LoadScionConfigFromEnv(); err == nil {
		t.Errorf("invalid address accepted")
	}
}

func TestPathManagerExplicitAPIAddress(t *testing.T) {
	a := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	b := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	pmA, err := newAPIPathManager(a)
	if err != nil {
		t.Fatal(err)
	}
	defer pmA.Close()
	pmB, err := newAPIPathManager(b)
	if err != nil {
		t.Fatal(err)
	}
	defer pmB.Close()
	getMetrics(t, a)
	getMetrics(t, b)

	// A taken address fails, naming the address and the variable.
	_, err = newAPIPathManager(a)
	if err == nil {
		t.Fatal("taken address accepted")
	}
	for _, want := range []string{a, EnvSCIONPathAPIAddress} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestPathManagerAPIAddressReopen(t *testing.T) {
	a := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	for i := 0; i < 3; i++ {
		pm, err := newAPIPathManager(a)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		getMetrics(t, a)
		pm.Close()
	}
}

func TestParseMarketplaceAddress(t *testing.T) {
	for _, ok := range []string{"[71-2:0:5c,127.0.0.1]:31888",
		"https://127.0.0.1:8443",
		"http://host:8443/x"} {
		if err := ParseMarketplaceAddress(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"nonsense",
		"host",
		"host:8443",
		"127.0.0.1:8443",
		"ftp://host:21",
		"https://host:0",
		"[127.0.0.1]:80",
		"[xx,127.0.0.1]:31888",
		"[71-2:0:5c,]:31888",
		"[71-2:0:5c,127.0.0.1]",
		"a b:80",
		":80"} {
		if err := ParseMarketplaceAddress(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLoadHummingbirdMarketplaceAddress(t *testing.T) {
	t.Setenv(EnvHummingbirdBandwidth, "1mbps")
	t.Setenv(EnvMarketplaceJWT, "token")
	t.Setenv(EnvHummingbirdDuration, "60s")

	cfg, err := LoadHummingbirdConfigFromEnv()
	if err != nil || cfg.MarketplaceAddress != "" {
		t.Fatalf("unset: %q, %v", cfg.MarketplaceAddress, err)
	}
	t.Setenv(EnvHummingbirdMarketplaceAddress, "[71-2:0:5c,127.0.0.1]:31888")
	cfg, err = LoadHummingbirdConfigFromEnv()
	if err != nil || cfg.MarketplaceAddress != "[71-2:0:5c,127.0.0.1]:31888" {
		t.Fatalf("valid: %q, %v", cfg.MarketplaceAddress, err)
	}
	t.Setenv(EnvHummingbirdMarketplaceAddress, "garbage")
	if _, err = LoadHummingbirdConfigFromEnv(); err == nil {
		t.Error("malformed address accepted")
	}
	// Ignored, not an error, when Hummingbird is disabled.
	t.Setenv(EnvHummingbirdBandwidth, "")
	if cfg, err = LoadHummingbirdConfigFromEnv(); err != nil || cfg.Enabled || cfg.MarketplaceAddress != "" {
		t.Errorf("disabled: %+v, %v", cfg, err)
	}
}

func TestBuyReservationUsesMarketplaceAddress(t *testing.T) {
	const address = "[71-2:0:5c,127.0.0.1]:31888"
	var got marketplace.ReservationRequest
	orig := oneShotReservation
	oneShotReservation = func(_ context.Context, _ snet.Path, _ string, _ snet.PathQuerier,
		_ snet.Topology, _ bool, req marketplace.ReservationRequest,
	) (*snetpath.Reservation, error) {
		got = req
		return nil, fmt.Errorf("stop")
	}
	t.Cleanup(func() { oneShotReservation = orig })

	dst := addr.MustParseIA("1-ff00:0:111")
	d := &fakeDaemon{refreshed: []snet.Path{testPath(2)}, paths: []snet.Path{testPath(2)}}
	pm := newTestPathManager(t, d)
	pm.humm = DefaultHummingbirdConfig()
	pm.humm.Duration = time.Minute
	pm.humm.MarketplaceAddress = address
	pm.metrics = wireguardMetrics
	pm.RegisterEndpoint(dst)
	_, _, _ = pm.buyReservation(context.Background(), dst, time.Now())
	if got.MarketplaceAddress != address {
		t.Errorf("request carries %q, want %q", got.MarketplaceAddress, address)
	}
}
