package tirisexporter

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"
)

// metricsExporter implements the metrics exporter for Tiris.
type metricsExporter struct {
	*tirisExporter
}

// createMetricsExporter creates a new metrics exporter instance.
func createMetricsExporter(
	ctx context.Context,
	set exporter.Settings,
	cfg component.Config,
) (exporter.Metrics, error) {
	eCfg := cfg.(*Config)

	// Validate configuration
	if err := eCfg.Validate(); err != nil {
		return nil, err
	}

	// Create base exporter
	base, err := newExporter(eCfg, set.Logger)
	if err != nil {
		return nil, err
	}

	return &metricsExporter{tirisExporter: base}, nil
}

// Capabilities returns the capabilities of the metrics exporter.
func (e *metricsExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// Start initializes the metrics exporter.
func (e *metricsExporter) Start(ctx context.Context, host component.Host) error {
	return e.start(ctx, host)
}

// Shutdown stops the metrics exporter.
func (e *metricsExporter) Shutdown(ctx context.Context) error {
	return e.shutdown(ctx)
}

// ConsumeMetrics exports metrics to the Tiris backend.
func (e *metricsExporter) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	// Marshal metrics to OTLP protobuf format
	marshaler := &pmetric.ProtoMarshaler{}
	body, err := marshaler.MarshalMetrics(md)
	if err != nil {
		return err
	}

	e.logger.Info("Exporting metrics to Tiris",
		zap.Int("metric_count", md.MetricCount()),
		zap.Int("data_point_count", md.DataPointCount()),
		zap.Int("resource_metrics", md.ResourceMetrics().Len()),
	)

	// Send to Tiris backend (via /api prefix which nginx routes to backend)
	err = e.sendOTLP(ctx, "/api/otlp/v1/metrics", body)
	if err != nil {
		e.logger.Error("Failed to export metrics", zap.Error(err))
		return err
	}
	e.logger.Info("Successfully exported metrics to Tiris")
	return nil
}
