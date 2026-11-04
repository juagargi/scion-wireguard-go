package conn

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/types"
	humm "github.com/scionproto/scion/pkg/hummingbird"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/path/pathpol"
)

func TestRenewalSchedule(t *testing.T) {
	expiry := time.Date(2026, 9, 16, 12, 0, 30, 0, time.UTC)
	requestAt, handoverAt, startAt := renewalSchedule(expiry, 20*time.Second, 15*time.Second, -time.Second)

	if got, want := requestAt, expiry.Add(-20*time.Second); !got.Equal(want) {
		t.Errorf("requestAt = %s, want %s", got, want)
	}
	if got, want := handoverAt, expiry.Add(-15*time.Second); !got.Equal(want) {
		t.Errorf("handoverAt = %s, want %s", got, want)
	}
	if got, want := startAt, expiry.Add(-16*time.Second); !got.Equal(want) {
		t.Errorf("startAt = %s, want %s", got, want)
	}

	// The replacement is bought before it is needed, is valid before it carries
	// traffic, and takes over before the reservation it replaces expires.
	if !requestAt.Before(startAt) || !startAt.Before(handoverAt) || !handoverAt.Before(expiry) {
		t.Errorf("out of order: request %s, start %s, handover %s, expiry %s",
			requestAt, startAt, handoverAt, expiry)
	}
}

func TestHummingbirdConfigValidate(t *testing.T) {
	valid := DefaultHummingbirdConfig()
	valid.Enabled = true
	valid.JWT = "token"
	valid.BandwidthKbps = 1000
	valid.Duration = 60 * time.Second

	if err := valid.Validate(); err != nil {
		t.Fatalf("default configuration rejected: %v", err)
	}
	if disabled := (HummingbirdConfig{}); disabled.Validate() != nil {
		t.Errorf("a disabled configuration must always be valid")
	}

	for name, break_ := range map[string]func(*HummingbirdConfig){
		"no token":        func(c *HummingbirdConfig) { c.JWT = "" },
		"no bandwidth":    func(c *HummingbirdConfig) { c.BandwidthKbps = 0 },
		"no duration":     func(c *HummingbirdConfig) { c.Duration = 0 },
		"lease too long":  func(c *HummingbirdConfig) { c.Duration = maxReservationDuration + time.Second },
		"overlap > ahead": func(c *HummingbirdConfig) { c.ReservationOverlap = c.RenewalAhead + time.Second },
		"ahead > lease":   func(c *HummingbirdConfig) { c.RenewalAhead = c.Duration },
		"future start":    func(c *HummingbirdConfig) { c.StartOffset = time.Second },
	} {
		cfg := valid
		break_(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadHummingbirdPathToMarketplaceFilter(t *testing.T) {
	t.Setenv(EnvHummingbirdBandwidth, "1mbps")
	t.Setenv(EnvMarketplaceJWT, "token")
	t.Setenv(EnvHummingbirdDuration, "60s")

	cfg, err := LoadHummingbirdConfigFromEnv()
	if err != nil {
		t.Fatalf("loading without filter: %v", err)
	}
	if cfg.PathToMarketplace != nil {
		t.Errorf("no filter given, got %q", cfg.PathToMarketplace)
	}

	t.Setenv(EnvHummingbirdPathToMarketplaceFilter, "1-ff00:0:110#2 0*")
	cfg, err = LoadHummingbirdConfigFromEnv()
	if err != nil {
		t.Fatalf("loading with filter: %v", err)
	}
	if cfg.PathToMarketplace == nil || cfg.PathToMarketplace.String() != "1-ff00:0:110#2 0*" {
		t.Errorf("filter not loaded, got %v", cfg.PathToMarketplace)
	}

	t.Setenv(EnvHummingbirdPathToMarketplaceFilter, "not a sequence ((")
	if _, err := LoadHummingbirdConfigFromEnv(); err == nil {
		t.Errorf("malformed filter accepted")
	}
}

// fakeDaemon answers path requests with paths, and the refreshed ones with refreshed.
type fakeDaemon struct {
	daemon.Connector
	paths, refreshed []snet.Path
	refreshes        int
}

func (d *fakeDaemon) Paths(_ context.Context, _, _ addr.IA, f types.PathReqFlags) ([]snet.Path, error) {
	if f.Refresh {
		d.refreshes++
		return d.refreshed, nil
	}
	return d.paths, nil
}

// testPath is a path from 1-ff00:0:110 leaving through egress to 1-ff00:0:111.
func testPath(egress iface.ID) snet.Path {
	src, dst := addr.MustParseIA("1-ff00:0:110"), addr.MustParseIA("1-ff00:0:111")
	return snetpath.Path{Src: src, Dst: dst, Meta: snet.PathMetadata{
		Interfaces: []snet.PathInterface{{IA: src, ID: egress}, {IA: dst, ID: 1}},
	}}
}

func TestSequenceQuerier(t *testing.T) {
	local, dst := addr.MustParseIA("1-ff00:0:110"), addr.MustParseIA("1-ff00:0:111")
	sequence, err := pathpol.NewSequence("1-ff00:0:110#3 0*")
	if err != nil {
		t.Fatal(err)
	}
	egress := func(p snet.Path) iface.ID { return p.Metadata().Interfaces[0].ID }

	d := &fakeDaemon{paths: []snet.Path{testPath(2), testPath(3), testPath(3)}}
	paths, err := sequenceQuerier{d: d, local: local, sequence: sequence}.Query(context.Background(), dst)
	if err != nil {
		t.Fatalf("matching path not found: %v", err)
	}
	if len(paths) != 1 || egress(paths[0]) != 3 || d.refreshes != 0 {
		t.Errorf("want the first matching path without refreshing, got %v after %d refreshes",
			paths, d.refreshes)
	}

	d = &fakeDaemon{paths: []snet.Path{testPath(2)}, refreshed: []snet.Path{testPath(2), testPath(3)}}
	paths, err = sequenceQuerier{d: d, local: local, sequence: sequence}.Query(context.Background(), dst)
	if err != nil || len(paths) != 1 || egress(paths[0]) != 3 {
		t.Errorf("want the matching path after refreshing, got %v, %v", paths, err)
	}

	d = &fakeDaemon{paths: []snet.Path{testPath(2)}, refreshed: []snet.Path{testPath(2)}}
	if _, err = (sequenceQuerier{d: d, local: local, sequence: sequence}).Query(context.Background(), dst); err == nil {
		t.Errorf("no path matches, yet no error")
	}
}

func TestLoadHummingbirdPartial(t *testing.T) {
	t.Setenv(EnvHummingbirdBandwidth, "1mbps")
	t.Setenv(EnvMarketplaceJWT, "token")
	t.Setenv(EnvHummingbirdDuration, "60s")

	cfg, err := LoadHummingbirdConfigFromEnv()
	if err != nil || cfg.Partial != nil {
		t.Fatalf("without %s every AS must be reserved, got %v, %v",
			EnvHummingbirdPartial, cfg.Partial, err)
	}

	t.Setenv(EnvHummingbirdPartial, "!1-ff00:0:110")
	if cfg, err = LoadHummingbirdConfigFromEnv(); err != nil || cfg.Partial == nil {
		t.Fatalf("deny-list not loaded: %v, %v", cfg.Partial, err)
	}

	t.Setenv(EnvHummingbirdPartial, "1-ff00:0:110,!1-ff00:0:111")
	if _, err := LoadHummingbirdConfigFromEnv(); err == nil {
		t.Errorf("a list mixing allowed and denied ASes was accepted")
	}
}

func TestPartialSelection(t *testing.T) {
	// testPath crosses 1-ff00:0:110 and then 1-ff00:0:111.
	path := testPath(3)
	parse := func(raw string) *humm.ASFilter {
		filter, err := humm.ParseASFilter(raw)
		if err != nil {
			t.Fatal(err)
		}
		return filter
	}

	for name, tc := range map[string]struct {
		partial *humm.ASFilter
		want    []int
		err     error
	}{
		"every AS by default":     {partial: nil, want: nil},
		"every AS listed":         {partial: parse("1-ff00:0:110,1-ff00:0:111"), want: nil},
		"deny-list":               {partial: parse("!1-ff00:0:110"), want: []int{1}},
		"allow-list":              {partial: parse("1-ff00:0:110"), want: []int{0}},
		"no AS of the path":       {partial: parse("1-ff00:0:999"), err: errNoASSelected},
		"every AS of path denied": {partial: parse("!1-ff00:0:110,!1-ff00:0:111"), err: errNoASSelected},
	} {
		got, err := HummingbirdConfig{Partial: tc.partial}.partialSelection(path)
		if !errors.Is(err, tc.err) || fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s: got %v, %v; want %v, %v", name, got, err, tc.want, tc.err)
		}
		if tc.want == nil && tc.err == nil && got != nil {
			t.Errorf("%s: every AS must be requested as nil, got %v", name, got)
		}
	}
}
