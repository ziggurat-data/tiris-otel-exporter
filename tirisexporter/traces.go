package tirisexporter

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap"
)

// tracesExporter implements the traces exporter for Tiris.
type tracesExporter struct {
	*tirisExporter
}

// createTracesExporter creates a new traces exporter instance.
func createTracesExporter(
	ctx context.Context,
	set exporter.Settings,
	cfg component.Config,
) (exporter.Traces, error) {
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

	return &tracesExporter{tirisExporter: base}, nil
}

// Capabilities returns the capabilities of the traces exporter.
func (e *tracesExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// Start initializes the traces exporter.
func (e *tracesExporter) Start(ctx context.Context, host component.Host) error {
	return e.start(ctx, host)
}

// Shutdown stops the traces exporter.
func (e *tracesExporter) Shutdown(ctx context.Context) error {
	return e.shutdown(ctx)
}

// ConsumeTraces exports traces to the Tiris backend.
func (e *tracesExporter) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	// Marshal traces to OTLP protobuf format
	marshaler := &ptrace.ProtoMarshaler{}
	body, err := marshaler.MarshalTraces(td)
	if err != nil {
		return err
	}

	e.logger.Info("Exporting traces to Tiris",
		zap.Int("span_count", td.SpanCount()),
		zap.Int("resource_spans", td.ResourceSpans().Len()),
	)

	// Send to Tiris backend (via /api prefix which nginx routes to backend)
	err = e.sendOTLP(ctx, "/api/otlp/v1/traces", body)
	if err != nil {
		e.logger.Error("Failed to export traces", zap.Error(err))
		return err
	}
	e.logger.Info("Successfully exported traces to Tiris")
	return nil
}
