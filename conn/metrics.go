package conn

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/scionproto/scion/pkg/snet"
)

const (
	// Metrics' prefix.
	metricsNamespace = "wireguard"

	// The label on reservation_setup_duration_seconds, and its two values.
	labelResult = "result"
	resultOK    = "ok"
	resultErr   = "err"
)

type Metrics struct {
	// SCIONPacketConnMetrics is filled in by snet's SCIONPacketConn when the bind runs
	// without USE_BATCH, and by ScionBatchConn itself when it runs with it.
	// The two are never active at the same time.
	SCIONPacketConnMetrics snet.SCIONPacketConnMetrics

	// reservationSetupDuration is observed once per purchase, under labelResult.
	// Use ObserveReservationSetup rather accessing the variable directly.
	reservationSetupDuration *prometheus.HistogramVec
}

// NewMetrics registers every series this package exports with the default registry.
// Call it once: promauto registers eagerly and panics on a name that is already taken.
func NewMetrics() Metrics {
	return Metrics{
		SCIONPacketConnMetrics: snet.SCIONPacketConnMetrics{
			// Bytes and packets are counted on the underlay, so the SCION and UDP
			// headers are part of them and a packet is counted regardless of its content:
			// payload, SCMP, or something that does not parse at all.
			ReadBytes: newCounter("received_bytes_total",
				"Total number of bytes read from the underlay, SCION and UDP headers included"),
			WriteBytes: newCounter("sent_bytes_total",
				"Total number of bytes written to the underlay, SCION and UDP headers included"),
			ReadPackets: newCounter("received_packets_total",
				"Total number of packets read from the underlay"),
			WritePackets: newCounter("sent_packets_total",
				"Total number of packets written to the underlay"),
			ParseErrors: newCounter("parse_errors_total",
				"Total number of received packets that could not be decoded as SCION"),
			SCMPErrors: newCounter("scmp_errors_total",
				"Total number of received SCMP packets that no handler was installed for"),
			UnderlayConnectionErrors: newCounter("underlay_connection_errors_total",
				"Total number of failed reads from the underlay connection"),
			Closes: newCounter("closes_total",
				"Total number of times the underlay connection was closed"),
		},
		reservationSetupDuration: newReservationHistogram(),
	}
}

// ObserveReservationSetup tells how long one marketplace purchase took.
//
// Both ok and error outcomes are timed, under their own label.
func (m Metrics) ObserveReservationSetup(took time.Duration, err error) {
	if m.reservationSetupDuration == nil {
		return
	}
	result := resultOK
	if err != nil {
		result = resultErr
	}
	m.reservationSetupDuration.WithLabelValues(result).Observe(took.Seconds())
}

// newCounter registers one unlabelled counter.
func newCounter(name, help string) prometheus.Counter {
	return promauto.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      name,
		Help:      help,
	})
}

// newReservationHistogram registers the delay of marketplace purchases.
//
// A histogram keeps a count, a sum and buckets, none of which a scrape can miss,
// and its _count child is the number of reservations bought, so it doubles as a counter too.
func newReservationHistogram() *prometheus.HistogramVec {
	hv := promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "reservation_setup_duration_seconds",
		Help:      "Time taken to search, buy and redeem assets at the marketplace",
		Buckets:   prometheus.ExponentialBuckets(0.01, 2, 11), // 10ms to 10.24s.
	}, []string{labelResult})
	for _, result := range []string{resultOK, resultErr} {
		hv.With(prometheus.Labels{labelResult: result}) // Run it with With instead of Observe.
	}
	return hv
}
