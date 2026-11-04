package conn

import (
	"context"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/path/pathpol"
)

type nopLogger struct{}

func (nopLogger) Verbosef(string, ...interface{}) {}
func (nopLogger) Errorf(string, ...interface{})   {}

// newTestPathManager returns a manager on d that neither refreshes in the
// background nor serves its HTTP API.
func newTestPathManager(t *testing.T, d *fakeDaemon, opts ...PathManagerOption) *PathManager {
	pm := &PathManager{
		d:       d,
		localIA: addr.MustParseIA("1-ff00:0:110"),
		policy:  PathPolicyFirst,
		cache:   make(map[addr.IA]*PathCacheEntry),
		filters: make(map[addr.IA]*pathpol.Sequence),
		log:     nopLogger{},
	}
	for _, opt := range opts {
		opt(pm)
	}
	pm.ctx, pm.cancel = context.WithCancel(context.Background())
	t.Cleanup(pm.cancel)
	return pm
}

func TestPathManagerFilter(t *testing.T) {
	dst := addr.MustParseIA("1-ff00:0:111")
	egress := func(p snet.Path) any { return p.Metadata().Interfaces[0].ID }
	via3, err := pathpol.NewSequence("1-ff00:0:110#3 0*")
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDaemon{refreshed: []snet.Path{testPath(2), testPath(3), testPath(4)}}

	// A filter given at creation applies from the first lookup on.
	pm := newTestPathManager(t, d, WithPathFilters(map[addr.IA]*pathpol.Sequence{dst: via3}))
	pm.RegisterEndpoint(dst)
	if paths := pm.getPaths(dst); len(paths) != 1 || egress(paths[0]) != egress(testPath(3)) {
		t.Fatalf("want only the path through interface 3, got %v", paths)
	}

	// Lifting it brings every path back right away.
	if err := pm.SetPathFilter(dst, nil); err != nil {
		t.Fatal(err)
	}
	if paths := pm.getPaths(dst); len(paths) != 3 {
		t.Fatalf("want all 3 paths without a filter, got %d", len(paths))
	}

	// Setting one on a destination in use selects among the matching paths only.
	if err := pm.SetPathFilter(dst, via3); err != nil {
		t.Fatal(err)
	}
	path, err := pm.GetPath(dst)
	if err != nil || egress(path) != egress(testPath(3)) {
		t.Fatalf("want the path through interface 3 selected, got %v, %v", path, err)
	}

	// A filter nothing matches leaves no path at all, rather than falling back.
	none, err := pathpol.NewSequence("1-ff00:0:110#9 0*")
	if err != nil {
		t.Fatal(err)
	}
	if err := pm.SetPathFilter(dst, none); err != nil {
		t.Fatal(err)
	}
	if _, err := pm.GetPath(dst); err == nil {
		t.Errorf("a filter matching no path still yields a path")
	}

	// A filter for a destination not in use is only remembered.
	other := addr.MustParseIA("1-ff00:0:112")
	if err := pm.SetPathFilter(other, via3); err != nil {
		t.Fatal(err)
	}
	if _, tracked := pm.cache[other]; tracked {
		t.Errorf("setting a filter started tracking %s", other)
	}
}
