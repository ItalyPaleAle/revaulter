package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type RevaulterMetrics struct {
	registry *prometheus.Registry

	requests *prometheus.CounterVec
	results  *prometheus.CounterVec
	latency  *prometheus.SummaryVec
}

func (m *RevaulterMetrics) Init() {
	m.registry = prometheus.NewRegistry()
	factory := promauto.With(m.registry)

	m.requests = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "revaulter_requests_total",
		Help: "The total number of requests per operation per key",
	}, []string{"operation", "key"})

	m.results = factory.NewCounterVec(prometheus.CounterOpts{
		Name: "revaulter_results_total",
		Help: "The total number of results per status",
	}, []string{"status"})

	m.latency = factory.NewSummaryVec(prometheus.SummaryOpts{
		Name: "revaulter_keyvault_latency_ms",
		Help: "The latency of requests to Azure Key Vault",
	}, []string{"vault"})
}

func (m *RevaulterMetrics) HTTPHandler() http.Handler {
	return promhttp.InstrumentMetricHandler(
		m.registry, promhttp.HandlerFor(
			prometheus.Gatherers{
				m.registry,
				prometheus.DefaultGatherer,
			},
			promhttp.HandlerOpts{},
		),
	)
}

func (m *RevaulterMetrics) RecordRequest(operation string, key string) {
	m.requests.
		WithLabelValues(operation, key).
		Inc()
}

func (m *RevaulterMetrics) RecordResult(status string) {
	m.results.
		WithLabelValues(status).
		Inc()
}

func (m *RevaulterMetrics) RecordLatency(vault string, latency time.Duration) {
	m.latency.
		WithLabelValues(vault).
		Observe(float64(latency.Microseconds()) / 1000)
}
