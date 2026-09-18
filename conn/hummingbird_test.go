package conn

import (
	"testing"
	"time"
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
