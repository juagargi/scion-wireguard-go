package conn

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// TestObserveReservationSetupLabelsTheOutcome checks that ObserveReservationSetup works
// with both okay and error values.
// pins down what the marketplace error that
// buyReservation passes in is for. A purchase that failed took time too, usually the
// most of it, and the gauge this replaced recorded it as if it had succeeded. The local
// topology never fails a purchase, so no integration run reaches this path.
func TestObserveReservationSetupLabelsTheOutcome(t *testing.T) {
	m, scrape := newTestMetrics(t)

	m.ObserveReservationSetup(70*time.Millisecond, nil)
	m.ObserveReservationSetup(90*time.Millisecond, nil)
	m.ObserveReservationSetup(4*time.Second, errors.New("no assets found"))

	exposition := scrape()
	if got := countLine(t, exposition, resultOK); got != "2" {
		t.Errorf("result=%s counted %s purchases, want 2", resultOK, got)
	}
	if got := countLine(t, exposition, resultErr); got != "1" {
		t.Errorf("result=%s counted %s purchases, want 1: a purchase that failed must "+
			"not be filed as one that worked", resultErr, got)
	}
}

// TestObserveReservationSetupExportsBothOutcomesFromTheStart covers the With calls in
// newReservationHistogram: a label that has never been observed would otherwise be
// missing from the exposition rather than reading 0.
func TestObserveReservationSetupExportsBothOutcomesFromTheStart(t *testing.T) {
	m, scrape := newTestMetrics(t)
	for _, result := range []string{resultOK, resultErr} {
		m.reservationSetupDuration.With(prometheus.Labels{labelResult: result})
	}

	exposition := scrape()
	for _, result := range []string{resultOK, resultErr} {
		if got := countLine(t, exposition, result); got != "0" {
			t.Errorf("result=%s starts at %s, want 0", result, got)
		}
	}
}

// TestObserveReservationSetupOnZeroMetrics covers a PathManager built without
// WithMetrics, where the histogram is nil.
func TestObserveReservationSetupOnZeroMetrics(t *testing.T) {
	var m Metrics
	m.ObserveReservationSetup(time.Second, errors.New("boom")) // must not panic
}

// newTestMetrics builds a Metrics on a registry of its own, and returns a scrape of that registry.
// It cannot call NewMetrics, which registers with the default registry that
// the package level wireguardMetrics has already claimed.
func newTestMetrics(t *testing.T) (Metrics, func() string) {
	t.Helper()
	hv := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "reservation_setup_duration_seconds",
		Help:      "under test",
		Buckets:   prometheus.ExponentialBuckets(0.01, 2, 11),
	}, []string{labelResult})
	registry := prometheus.NewRegistry()
	registry.MustRegister(hv)

	scrape := func() string {
		recorder := httptest.NewRecorder()
		promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).
			ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
		return recorder.Body.String()
	}
	return Metrics{reservationSetupDuration: hv}, scrape
}

// countLine finds one exposed sample and returns the text of its line, so that a failure
// message can show what was exported rather than just that a number was wrong.
func countLine(t *testing.T, exposition, result string) string {
	t.Helper()
	prefix := metricsNamespace + `_reservation_setup_duration_seconds_count{` +
		labelResult + `="` + result + `"}`
	for _, line := range strings.Split(exposition, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	t.Fatalf("no %s line in:\n%s", prefix, exposition)
	return ""
}
