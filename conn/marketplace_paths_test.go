package conn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
)

// fakeQuerier answers with paths or err, after gate is closed when gate is set.
type fakeQuerier struct {
	mu    sync.Mutex
	calls int
	paths []snet.Path
	err   error
	gate  chan struct{}
}

func (q *fakeQuerier) Query(ctx context.Context, _ addr.IA) ([]snet.Path, error) {
	q.mu.Lock()
	q.calls++
	gate, paths, err := q.gate, q.paths, q.err
	q.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return paths, err
}

func (q *fakeQuerier) set(paths []snet.Path, err error, gate chan struct{}) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.paths, q.err, q.gate = paths, err, gate
}

func (q *fakeQuerier) callCount() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.calls
}

// testClock is a clock the test advances; the background refreshes read it too.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestCachingQuerier(t *testing.T, q snet.PathQuerier) (*cachingQuerier, *testClock) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clock := &testClock{t: time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)}
	c := newCachingQuerier(ctx, q, nil)
	c.now = clock.now
	return c, clock
}

// queryEgress queries c for dst and returns the egress interface of the one path it expects.
func queryEgress(t *testing.T, c *cachingQuerier, dst addr.IA) iface.ID {
	t.Helper()
	paths, err := c.Query(context.Background(), dst)
	if err != nil || len(paths) != 1 {
		t.Fatalf("want one path, got %v, %v", paths, err)
	}
	return paths[0].Metadata().Interfaces[0].ID
}

// TestCachingQuerierAnswersFromCacheAndRefreshesInBackground checks that once paths are
// cached, a query never waits for the querier: it gets the cached paths, and the stale ones
// are refreshed in the background, once at a time.
func TestCachingQuerierAnswersFromCacheAndRefreshesInBackground(t *testing.T) {
	ctx, dst := context.Background(), addr.MustParseIA("1-ff00:0:111")
	q := &fakeQuerier{}
	c, clock := newTestCachingQuerier(t, q)
	expiry := clock.now().Add(time.Hour)

	q.set([]snet.Path{expiringPath(3, expiry)}, nil, nil)
	if got := queryEgress(t, c, dst); got != 3 || q.callCount() != 1 {
		t.Fatalf("first query: egress %d after %d calls, want 3 after 1", got, q.callCount())
	}
	if got := queryEgress(t, c, dst); got != 3 || q.callCount() != 1 {
		t.Fatalf("fresh cache: egress %d after %d calls, want the cached path and no call",
			got, q.callCount())
	}

	// Stale: the answer is still immediate, although the querier now blocks.
	gate := make(chan struct{})
	q.set([]snet.Path{expiringPath(4, expiry)}, nil, gate)
	clock.advance(c.refreshAge)
	if got := queryEgress(t, c, dst); got != 3 {
		t.Fatalf("stale cache: egress %d, want the cached 3 while refreshing", got)
	}
	waitFor(t, "the background refresh", func() bool { return q.callCount() == 2 })
	c.Query(ctx, dst) //nolint:errcheck // a second query must not start a second refresh
	if q.callCount() != 2 {
		t.Fatalf("%d calls, want one refresh at a time", q.callCount())
	}

	close(gate)
	waitFor(t, "the refreshed path", func() bool {
		paths, err := c.Query(ctx, dst)
		return err == nil && len(paths) == 1 && paths[0].Metadata().Interfaces[0].ID == 4
	})
	if q.callCount() != 2 {
		t.Fatalf("%d calls, want no refresh of the just refreshed paths", q.callCount())
	}
}

// TestCachingQuerierKeepsPathsWhenRefreshFails checks that a failed or empty refresh keeps
// the cached paths.
func TestCachingQuerierKeepsPathsWhenRefreshFails(t *testing.T) {
	ctx, dst := context.Background(), addr.MustParseIA("1-ff00:0:111")
	q := &fakeQuerier{}
	c, clock := newTestCachingQuerier(t, q)
	q.set([]snet.Path{expiringPath(3, clock.now().Add(time.Hour))}, nil, nil)
	c.Query(ctx, dst) //nolint:errcheck

	for i, failure := range []struct {
		paths []snet.Path
		err   error
	}{{nil, errors.New("daemon unreachable")}, {nil, nil}} {
		q.set(failure.paths, failure.err, nil)
		clock.advance(c.refreshAge)
		if got := queryEgress(t, c, dst); got != 3 {
			t.Fatalf("refresh %d: egress %d, want the cached 3", i, got)
		}
		waitFor(t, "the failed refresh to finish", func() bool {
			c.mu.Lock()
			defer c.mu.Unlock()
			return !c.entries[dst].refreshing
		})
		if got := queryEgress(t, c, dst); got != 3 {
			t.Fatalf("after failed refresh %d: egress %d, want the cached 3", i, got)
		}
	}
}

// TestCachingQuerierWaitsWithoutUsablePaths checks that Query asks the querier and waits for
// it when the cached paths are about to expire, or after forget.
func TestCachingQuerierWaitsWithoutUsablePaths(t *testing.T) {
	ctx, dst := context.Background(), addr.MustParseIA("1-ff00:0:111")
	q := &fakeQuerier{}
	c, clock := newTestCachingQuerier(t, q)
	q.set([]snet.Path{expiringPath(3, clock.now().Add(time.Minute))}, nil, nil)
	c.Query(ctx, dst) //nolint:errcheck

	q.set([]snet.Path{expiringPath(4, clock.now().Add(time.Hour))}, nil, nil)
	clock.advance(time.Minute - c.minLife + time.Second) // valid, but not for long enough
	if got := queryEgress(t, c, dst); got != 4 || q.callCount() != 2 {
		t.Fatalf("expiring cache: egress %d after %d calls, want a fresh 4 after 2",
			got, q.callCount())
	}

	q.set([]snet.Path{expiringPath(5, clock.now().Add(time.Hour))}, nil, nil)
	c.forget()
	if got := queryEgress(t, c, dst); got != 5 || q.callCount() != 3 {
		t.Fatalf("after forget: egress %d after %d calls, want a fresh 5 after 3",
			got, q.callCount())
	}

	q.set(nil, errors.New("daemon unreachable"), nil)
	c.forget()
	if _, err := c.Query(ctx, dst); err == nil {
		t.Fatalf("no cached path and a failing querier, yet no error")
	}
}
