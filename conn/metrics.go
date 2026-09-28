package conn

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/snet"
)

type Metrics struct {
	// SCIONPacketConnMetrics is filled in by snet's SCIONPacketConn when the bind runs
	// without USE_BATCH, and by ScionBatchConn itself when it runs with it.
	// The two are never active at the same time.
	SCIONPacketConnMetrics   snet.SCIONPacketConnMetrics
	ReservationSetupDuration metrics.Gauge
}

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
		ReservationSetupDuration: metrics.NewPromGauge(prom.NewGaugeVec("", "",
			"reservation_setup_duration_seconds",
			"Total time required to search, buy and redeem assets at the marketplace."+
				"Timed-out acquisitions will also increment this value", nil)),
	}
}

// newCounter registers an unlabelled counter and wraps it for snet.
func newCounter(name, help string) metrics.Counter {
	// SafeRegister rather than MustRegister.
	// Note that it returns the *existing* collector on a clash,
	// so two names that collide silently become one series: keep them distinct.
	c := metrics.NewPromCounter(prom.SafeRegister(
		prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: name,
			Help: help,
		}, nil)).(*prometheus.CounterVec),
	)
	// A CounterVec has no children until something writes to it, so a counter that has
	// not fired yet is missing from /metrics entirely.
	// Adding zero creates the series and leaves it reading 0.
	c.Add(0)
	return c
}
