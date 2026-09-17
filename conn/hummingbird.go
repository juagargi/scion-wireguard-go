package conn

import (
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/hummingbird/marketplace"
)

// Fixed marketplace purchase parameters.
const (
	// A path is only useful whole, so give up as soon as one of its ASes cannot be reserved.
	marketplaceBuyMode = marketplace.FailOnError

	// Reuse the reservations of an earlier attempt instead of buying them again.
	marketplaceFetchReservations = true

	// Allow splitting/combining marketplace assets.
	marketplaceCombineAssets = true

	// Somebody else may buy an asset between searching for it and paying for it.
	marketplacePurchaseRetries = 3
)

// Defaults of the tunable Hummingbird parameters.
const (
	defaultBandwidthKbps       = 1000
	defaultReservationDuration = 60 * time.Second
	defaultRenewalAhead        = 20 * time.Second
	defaultReservationOverlap  = 15 * time.Second
	defaultStartOffset         = -1 * time.Second
)

// HummingbirdConfig holds everything needed to buy Hummingbird reservations from
// the marketplaces of a path, and to keep them fresh.
type HummingbirdConfig struct {
	// Enabled turns the reservations on. Without it the tunnel travels on plain
	// SCION paths and no marketplace is ever contacted.
	Enabled bool

	// JWT authenticates this client at the marketplaces of the path.
	// Where those marketplaces live is not configured, but discovered from the metadata that
	// the ASes of the path advertise.
	JWT string

	// Insecure disables the validation of the marketplace server certificate.
	Insecure bool

	// MaxPrice is the most this client is willing to pay for one reservation.
	MaxPrice uint64

	// BandwidthKbps is the bandwidth to reserve in the forward direction.
	BandwidthKbps uint32

	// ReverseBandwidthKbps is the bandwidth to reserve in the reverse direction.
	// Zero makes the reservation unidirectional.
	ReverseBandwidthKbps uint32

	// Duration is how long every reservation lasts.
	Duration time.Duration

	// RenewalAhead is how long before a reservation expires its replacement is bought.
	// It has to cover a full marketplace roundtrip plus its retries.
	RenewalAhead time.Duration

	// ReservationOverlap is how long before a reservation expires the traffic
	// switches to its replacement. Only one reservation ever carries traffic;
	// the tail of the old one is paid for but deliberately left unused,
	// so that a slow handover cannot fall off the end of it.
	ReservationOverlap time.Duration

	// StartOffset is added to the instant at which a reservation starts carrying
	// traffic to obtain the start time it is bought with. It is negative: a
	// border router whose clock lags ours would drop a flyover that, by its own
	// clock, has not started yet.
	StartOffset time.Duration
}

// Bidirectional reports whether the reservations also cover the reverse
// direction, which the peer learns about from an extension on the forward path.
func (c HummingbirdConfig) Bidirectional() bool {
	return c.ReverseBandwidthKbps > 0
}

// Validate checks the parameters against each other. A disabled configuration is
// always valid, since none of its fields is ever read.
func (c HummingbirdConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.JWT == "" {
		return fmt.Errorf("missing marketplace token, set %s", EnvMarketplaceJWT)
	}
	if c.BandwidthKbps == 0 {
		return fmt.Errorf("reservation bandwidth must not be zero")
	}
	if c.Duration <= 0 {
		return fmt.Errorf("reservation duration must be positive, is %s", c.Duration)
	}
	if c.RenewalAhead < 0 {
		return fmt.Errorf("renewal ahead must not be negative, is %s", c.RenewalAhead)
	}
	if c.ReservationOverlap < 0 {
		return fmt.Errorf("reservation overlap must not be negative, is %s", c.ReservationOverlap)
	}
	if c.ReservationOverlap > c.RenewalAhead {
		return fmt.Errorf("reservation overlap %s must not exceed renewal ahead %s",
			c.ReservationOverlap, c.RenewalAhead)
	}
	if c.RenewalAhead >= c.Duration {
		return fmt.Errorf("renewal ahead %s must be shorter than the reservation duration %s",
			c.RenewalAhead, c.Duration)
	}
	if c.StartOffset > 0 {
		return fmt.Errorf("start offset must not be positive, is %s", c.StartOffset)
	}
	return nil
}

// renewalSchedule spreads the handover of a reservation expiring at expiry over
// three instants: when to buy the replacement, when to start sending on it, and
// the start time to buy it with.
//
// The two reservations are valid at the same time between startAt and expiry,
// but only one of them carries traffic: the old one until handoverAt, the new
// one from then on.
func renewalSchedule(
	expiry time.Time,
	ahead, overlap, startOffset time.Duration,
) (requestAt, handoverAt, startAt time.Time) {
	handoverAt = expiry.Add(-overlap)
	return expiry.Add(-ahead), handoverAt, handoverAt.Add(startOffset)
}
