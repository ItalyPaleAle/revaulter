package config

import (
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
)

// GetOtelResource returns the OpenTelemetry Resource object
func (c *Config) GetOtelResource(name string) (*resource.Resource, error) {
	return resource.Merge(
		resource.Default(),
		resource.NewSchemaless(
			semconv.ServiceName(name),
			semconv.ServiceInstanceID(c.GetInstanceID()),
			semconv.ServiceVersion(buildinfo.BuildId),
		),
	)
}
