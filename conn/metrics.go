package conn

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/scionproto/scion/pkg/metrics"
	"github.com/scionproto/scion/pkg/private/prom"
	"github.com/scionproto/scion/pkg/snet"
)

type Metrics struct {
	SCIONPacketConnMetrics   snet.SCIONPacketConnMetrics
	ReservationSetupDuration metrics.Gauge
	BytesSent                metrics.Counter
	BytesReceived            metrics.Counter
}

func NewMetrics() Metrics {

	return Metrics{
		SCIONPacketConnMetrics: snet.SCIONPacketConnMetrics{
			ReadBytes: metrics.NewPromCounter(prom.SafeRegister(
				prometheus.NewCounterVec(prometheus.CounterOpts{
					Name: "received_bytes_total",
					Help: "The total number of bytes received over the wireguard channel",
				}, nil)).(*prometheus.CounterVec),
			),
			WriteBytes: metrics.NewPromCounter(prom.SafeRegister(
				prometheus.NewCounterVec(prometheus.CounterOpts{
					Name: "sent_bytes_total",
					Help: "The total number of bytes sent over the wireguard channel",
				}, nil)).(*prometheus.CounterVec),
			),
		},
		ReservationSetupDuration: metrics.NewPromGauge(prom.NewGaugeVec("", "",
			"reservation_setup_duration_seconds",
			"Total time required to search, buy and redeem assets at the marketplace", nil)),
		BytesSent: metrics.NewPromCounter(prom.SafeRegister(
			prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: "sent_bytes_total",
				Help: "The total number of bytes sent over the wireguard channel",
			}, nil)).(*prometheus.CounterVec),
		),
		BytesReceived: metrics.NewPromCounter(prom.SafeRegister(
			prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: "received_bytes_total",
				Help: "The total number of bytes received over the wireguard channel",
			}, nil)).(*prometheus.CounterVec),
		),
	}
}
