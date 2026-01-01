package tirisexporter

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

// logsExporter implements the logs exporter for Tiris.
type logsExporter struct {
	*tirisExporter
}

// createLogsExporter creates a new logs exporter instance.
func createLogsExporter(
	ctx context.Context,
	set exporter.Settings,
	cfg component.Config,
) (exporter.Logs, error) {
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

	return &logsExporter{tirisExporter: base}, nil
}

// Capabilities returns the capabilities of the logs exporter.
func (e *logsExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// Start initializes the logs exporter.
func (e *logsExporter) Start(ctx context.Context, host component.Host) error {
	return e.start(ctx, host)
}

// Shutdown stops the logs exporter.
func (e *logsExporter) Shutdown(ctx context.Context) error {
	return e.shutdown(ctx)
}

// ConsumeLogs exports log records to the Tiris backend.
func (e *logsExporter) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	// Marshal logs to OTLP protobuf format
	marshaler := &plog.ProtoMarshaler{}
	body, err := marshaler.MarshalLogs(ld)
	if err != nil {
		return err
	}

	e.logger.Info("Exporting logs to Tiris",
		zap.Int("log_record_count", ld.LogRecordCount()),
		zap.Int("resource_logs", ld.ResourceLogs().Len()),
	)

	// Send to Tiris backend (via /api prefix which nginx routes to backend)
	err = e.sendOTLP(ctx, "/api/otlp/v1/logs", body)
	if err != nil {
		e.logger.Error("Failed to export logs", zap.Error(err))
		return err
	}
	e.logger.Info("Successfully exported logs to Tiris")
	return nil
}
