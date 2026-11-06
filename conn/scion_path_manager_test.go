package conn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
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
	d := &fakeDaemon{paths: []snet.Path{testPath(2), testPath(3), testPath(4)}}

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

// syncDaemon is a daemon whose answers can change while a manager's goroutines ask it.
type syncDaemon struct {
	daemon.Connector
	mu               sync.Mutex
	paths            []snet.Path
	refreshes, calls int
}

func (d *syncDaemon) Paths(_ context.Context, _, _ addr.IA, f types.PathReqFlags) ([]snet.Path, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if f.Refresh {
		d.refreshes++
	}
	return d.paths, nil
}

func (d *syncDaemon) set(paths ...snet.Path) {
	d.mu.Lock()
	d.paths = paths
	d.mu.Unlock()
}

func (d *syncDaemon) counts() (calls, refreshes int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls, d.refreshes
}

func newSyncPathManager(t *testing.T, d *syncDaemon) *PathManager {
	pm := newTestPathManager(t, &fakeDaemon{})
	pm.d = d
	return pm
}

// expiringPath is testPath(egress) that expires at expiry.
func expiringPath(egress iface.ID, expiry time.Time) snet.Path {
	p := testPath(egress).(snetpath.Path)
	p.Meta.Expiry = expiry
	return p
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPathManagerPeriodicRefreshUsesDaemonCache(t *testing.T) {
	dst := addr.MustParseIA("1-ff00:0:111")
	d := &syncDaemon{paths: []snet.Path{testPath(2)}}
	pm := newSyncPathManager(t, d)
	pm.RegisterEndpoint(dst)
	pm.refreshAll()
	if _, refreshes := d.counts(); refreshes != 0 {
		t.Errorf("periodic refreshes bypassed the daemon cache %d times", refreshes)
	}
}

func TestPathManagerKeepsUnexpiredPathsOnEmptyAnswer(t *testing.T) {
	dst := addr.MustParseIA("1-ff00:0:111")
	future := time.Now().Add(time.Hour)
	d := &syncDaemon{paths: []snet.Path{expiringPath(2, future), expiringPath(3, future)}}
	pm := newSyncPathManager(t, d)
	pm.RegisterEndpoint(dst)

	d.set()
	if err := pm.refreshOne(dst, false); !errors.Is(err, errNoPathsKeptOld) {
		t.Fatalf("want errNoPathsKeptOld, got %v", err)
	}
	if got := len(pm.getPaths(dst)); got != 2 {
		t.Fatalf("an empty answer replaced the cached paths: %d left, want 2", got)
	}
	if _, err := pm.GetPath(dst); err != nil {
		t.Errorf("no path to use after an empty answer: %v", err)
	}

	// The retry loop asks again and picks up the paths as soon as they are back.
	d.set(expiringPath(4, future))
	waitFor(t, "the retry to replace the paths", func() bool {
		paths := pm.getPaths(dst)
		return len(paths) == 1 && paths[0].Metadata().Interfaces[0].ID == 4
	})
	if _, refreshes := d.counts(); refreshes == 0 {
		t.Errorf("the retry did not force a lookup")
	}
	waitFor(t, "the retry loop to end", func() bool {
		pm.mu.RLock()
		defer pm.mu.RUnlock()
		return !pm.retrying[dst]
	})
}

func TestPathManagerEmptyAnswerReplacesExpiredPaths(t *testing.T) {
	dst := addr.MustParseIA("1-ff00:0:111")
	d := &syncDaemon{paths: []snet.Path{expiringPath(2, time.Now().Add(-time.Minute))}}
	pm := newSyncPathManager(t, d)
	pm.RegisterEndpoint(dst)
	d.set()
	if err := pm.refreshOne(dst, false); err != nil {
		t.Fatal(err)
	}
	if got := len(pm.getPaths(dst)); got != 0 {
		t.Errorf("expired paths survived an empty answer: %d left", got)
	}
}

func TestPathManagerReportPathFailureForcesRefresh(t *testing.T) {
	dst := addr.MustParseIA("1-ff00:0:111")
	d := &syncDaemon{paths: []snet.Path{testPath(2)}}
	pm := newSyncPathManager(t, d)
	pm.RegisterEndpoint(dst)

	d.set(testPath(3))
	pm.ReportPathFailure(dst)
	waitFor(t, "the forced refresh", func() bool {
		paths := pm.getPaths(dst)
		return len(paths) == 1 && paths[0].Metadata().Interfaces[0].ID == 3
	})
	_, refreshes := d.counts()
	if refreshes != 1 {
		t.Errorf("want one forced lookup, got %d", refreshes)
	}

	// Reports in quick succession do not hammer the daemon.
	pm.ReportPathFailure(dst)
	pm.ReportPathFailure(dst)
	time.Sleep(50 * time.Millisecond)
	if _, refreshes = d.counts(); refreshes != 1 {
		t.Errorf("repeated failure reports forced %d lookups, want 1", refreshes)
	}
}

func TestPathManagerRetriesWithoutCachedPaths(t *testing.T) {
	dst := addr.MustParseIA("1-ff00:0:111")
	d := &syncDaemon{}
	pm := newSyncPathManager(t, d)
	pm.RegisterEndpoint(dst)
	if got := len(pm.getPaths(dst)); got != 0 {
		t.Fatalf("want no paths yet, got %d", got)
	}

	// The retry loop finds the paths as soon as the daemon has them, long before a periodic refresh.
	d.set(testPath(2))
	waitFor(t, "the retry to find the paths", func() bool { return len(pm.getPaths(dst)) == 1 })
}
