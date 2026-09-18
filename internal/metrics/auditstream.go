package metrics

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	api "go.opentelemetry.io/otel/metric"
)

// AuditStreamMetrics implements siem.Metrics on top of RevaulterMetrics
//
// It is a separate type so the shipper's generic method names (RecordEvents, RecordBatch, …) do not have to collide with the application-level ones on RevaulterMetrics
type AuditStreamMetrics struct {
	m *RevaulterMetrics
}

// AuditStream returns the audit log stream's view of the metrics
func (m *RevaulterMetrics) AuditStream() *AuditStreamMetrics {
	return &AuditStreamMetrics{m: m}
}

// RecordEvents records that count audit events reached the given outcome ("sent" or "filtered")
func (a *AuditStreamMetrics) RecordEvents(outcome string, count int64) {
	if a == nil || a.m == nil {
		return
	}

	a.m.auditStreamEvents.Add(
		context.Background(),
		count,
		api.WithAttributeSet(
			attribute.NewSet(
				attribute.KeyValue{Key: "outcome", Value: attribute.StringValue(outcome)},
			),
		),
	)
}

// RecordBatch records the outcome of an audit event batch delivery ("sent", "retried" or "failed")
func (a *AuditStreamMetrics) RecordBatch(outcome string) {
	if a == nil || a.m == nil {
		return
	}

	a.m.auditStreamBatches.Add(
		context.Background(),
		1,
		api.WithAttributeSet(
			attribute.NewSet(
				attribute.KeyValue{Key: "outcome", Value: attribute.StringValue(outcome)},
			),
		),
	)
}

// RecordLag records how far the audit log stream has fallen behind
// This is the signal to alert on: it covers collector outages, misconfiguration and a stalled shipper in one
func (a *AuditStreamMetrics) RecordLag(seconds float64) {
	if a == nil || a.m == nil {
		return
	}

	a.m.auditStreamLag.Record(context.Background(), seconds)
}

// RecordBacklog records how many audit events are waiting past the cursor
func (a *AuditStreamMetrics) RecordBacklog(count int64) {
	if a == nil || a.m == nil {
		return
	}

	a.m.auditStreamBacklog.Record(context.Background(), count)
}
