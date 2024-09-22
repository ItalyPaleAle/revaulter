package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	api "go.opentelemetry.io/otel/metric"
	metricSdk "go.opentelemetry.io/otel/sdk/metric"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/italypaleale/revaulter/pkg/config"
)

type RevaulterMetrics struct {
	prometheusRegisterer *prom.Registry

	serverRequests api.Float64Histogram
	requests       api.Int64Counter
	results        api.Int64Counter
	latency        api.Float64Histogram
}

func NewRevaulterMetrics(ctx context.Context, log *slog.Logger) (m *RevaulterMetrics, shutdownFn func(ctx context.Context) error, err error) {
	cfg := config.Get()

	m = &RevaulterMetrics{}
	providerOpts := make([]metricSdk.Option, 0, 2)

	// If we have an OpenTelemetry Collector for metrics, add that
	exporter, err := cfg.GetMetricsExporter(ctx, log)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init metrics: %w", err)
	}
	if exporter != nil {
		providerOpts = append(providerOpts,
			metricSdk.WithReader(metricSdk.NewPeriodicReader(exporter)),
			metricSdk.WithResource(cfg.GetOtelResource(buildinfo.AppName)),
		)
	}

	// If the metrics server is enabled, create a Prometheus exporter
	if cfg.MetricsServerEnabled {
		m.prometheusRegisterer = prom.NewRegistry()
		promExporter, err := prometheus.New(
			prometheus.WithRegisterer(m.prometheusRegisterer),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create Prometheus exporter: %w", err)
		}
		providerOpts = append(providerOpts, metricSdk.WithReader(promExporter))
	}

	// If there's no exporter configured, stop here
	if len(providerOpts) == 0 && log != nil {
		log.WarnContext(ctx, "Metrics are enabled in the configuration, but no metrics exporter is configured. Make sure to enable the metrics server and/or configure an OpenTelemetry metric collector")
		return nil, nil, nil
	}

	provider := metricSdk.NewMeterProvider(providerOpts...)
	meter := provider.Meter(buildinfo.AppName)

	m.serverRequests, err = meter.Float64Histogram(
		"revaulter_server_requests",
		api.WithUnit("ms"),
		api.WithDescription("Requests processed by the server and duration in milliseconds"),
		api.WithExplicitBucketBoundaries(1, 2.5, 5, 10, 25, 50, 100, 250, 500),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create revaulter_server_requests meter: %w", err)
	}

	m.requests, err = meter.Int64Counter(
		"revaulter_requests",
		api.WithDescription("The total number of requests per operation per key"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create revaulter_requests meter: %w", err)
	}

	m.results, err = meter.Int64Counter(
		"revaulter_results",
		api.WithDescription("The total number of results per status"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create revaulter_results meter: %w", err)
	}

	m.latency, err = meter.Float64Histogram(
		"revaulter_keyvault_latency",
		api.WithUnit("ms"),
		api.WithDescription("The latency of requests to Azure Key Vault"),
		api.WithExplicitBucketBoundaries(1, 2.5, 5, 10, 25, 50, 100, 250, 500),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create revaulter_keyvault_latency meter: %w", err)
	}

	return m, provider.Shutdown, nil
}

func (m *RevaulterMetrics) HTTPHandler() http.Handler {
	if m.prometheusRegisterer == nil {
		// This indicates a development-time error
		panic("called HTTPHandler when metrics server is disabled")
	}

	return promhttp.InstrumentMetricHandler(
		m.prometheusRegisterer,
		promhttp.HandlerFor(
			prom.Gatherers{
				m.prometheusRegisterer,
				prom.DefaultGatherer,
			},
			promhttp.HandlerOpts{},
		),
	)
}

// RecordServerRequest records a request processed by the server.
func (m *RevaulterMetrics) RecordServerRequest(route string, status int, duration time.Duration) {
	if m == nil {
		return
	}

	m.serverRequests.Record(
		context.Background(),
		float64(duration.Microseconds())/1000,
		api.WithAttributeSet(
			attribute.NewSet(
				attribute.KeyValue{Key: "status", Value: attribute.IntValue(status)},
				attribute.KeyValue{Key: "route", Value: attribute.StringValue(route)},
			),
		),
	)
}

func (m *RevaulterMetrics) RecordRequest(operation string, key string) {
	if m == nil {
		return
	}

	m.requests.Add(
		context.Background(),
		1,
		api.WithAttributeSet(
			attribute.NewSet(
				attribute.KeyValue{Key: "operation", Value: attribute.StringValue(operation)},
				attribute.KeyValue{Key: "key", Value: attribute.StringValue(key)},
			),
		),
	)
}

func (m *RevaulterMetrics) RecordResult(status string) {
	if m == nil {
		return
	}

	m.results.Add(
		context.Background(),
		1,
		api.WithAttributeSet(
			attribute.NewSet(
				attribute.KeyValue{Key: "status", Value: attribute.StringValue(status)},
			),
		),
	)
}

func (m *RevaulterMetrics) RecordLatency(vault string, latency time.Duration) {
	if m == nil {
		return
	}

	m.latency.Record(
		context.Background(),
		float64(latency.Microseconds())/1000,
		api.WithAttributeSet(
			attribute.NewSet(
				attribute.KeyValue{Key: "vault", Value: attribute.StringValue(vault)},
			),
		),
	)
}
