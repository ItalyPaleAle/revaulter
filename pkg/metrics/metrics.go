package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel/attribute"
	api "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/italypaleale/revaulter/pkg/config"
)

const prefix = "revaulter"

type RevaulterMetrics struct {
	serverRequests api.Float64Histogram
	requests       api.Int64Counter
	results        api.Int64Counter
	latency        api.Float64Histogram
}

func NewRevaulterMetrics(ctx context.Context, log *slog.Logger) (m *RevaulterMetrics, shutdownFn func(ctx context.Context) error, err error) {
	cfg := config.Get()
	m = &RevaulterMetrics{}

	resource, err := cfg.GetOtelResource(buildinfo.AppName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get OpenTelemetry resource: %w", err)
	}

	// Get the metric reader
	// If the env var OTEL_METRICS_EXPORTER is empty, we set it to "none"
	if os.Getenv("OTEL_METRICS_EXPORTER") == "" {
		os.Setenv("OTEL_METRICS_EXPORTER", "none")
	}
	mr, err := autoexport.NewMetricReader(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize OpenTelemetry metric reader: %w", err)
	}

	mp := metric.NewMeterProvider(
		metric.WithResource(resource),
		metric.WithReader(mr),
	)
	meter := mp.Meter(prefix)

	m.serverRequests, err = meter.Float64Histogram(
		prefix+"_server_requests",
		api.WithUnit("ms"),
		api.WithDescription("Requests processed by the server and duration in milliseconds"),
		api.WithExplicitBucketBoundaries(1, 2.5, 5, 10, 25, 50, 100, 250, 500),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create %s_server_requests meter: %w", prefix, err)
	}

	m.requests, err = meter.Int64Counter(
		prefix+"_requests",
		api.WithDescription("The total number of requests per operation per key"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create %s_requests meter: %w", prefix, err)
	}

	m.results, err = meter.Int64Counter(
		prefix+"_results",
		api.WithDescription("The total number of results per status"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create %s_results meter: %w", prefix, err)
	}

	m.latency, err = meter.Float64Histogram(
		prefix+"_keyvault_latency",
		api.WithUnit("ms"),
		api.WithDescription("The latency of requests to Azure Key Vault"),
		api.WithExplicitBucketBoundaries(20, 50, 100, 200, 400, 600, 800, 1000, 1500, 2500),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create %s_keyvault_latency meter: %w", prefix, err)
	}

	return m, mp.Shutdown, nil
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
