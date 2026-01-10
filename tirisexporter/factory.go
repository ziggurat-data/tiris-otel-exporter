package tirisexporter

import (
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/exporter"
)

const (
	// typeStr is the value of "type" key in configuration.
	typeStr   = "tiris"
	stability = component.StabilityLevelBeta
)

// NewFactory creates a factory for Tiris exporter.
func NewFactory() exporter.Factory {
	return exporter.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		exporter.WithLogs(createLogsExporter, stability),
		exporter.WithMetrics(createMetricsExporter, stability),
		exporter.WithTraces(createTracesExporter, stability),
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		ClientConfig: confighttp.ClientConfig{
			Endpoint: "",
			Timeout:  30 * time.Second,
		},
		JWTLifetime:        59, // minutes
		TokenRefreshBuffer: 5,  // minutes
	}
}

// createLogsExporter is implemented in logs.go
