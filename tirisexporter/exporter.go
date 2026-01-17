package tirisexporter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"go.opentelemetry.io/collector/component"
	"go.uber.org/zap"
)

// tirisExporter is the base exporter that handles Snowflake authentication and HTTP requests.
type tirisExporter struct {
	config       *Config
	logger       *zap.Logger
	tokenManager *TokenManager
	httpClient   *http.Client
}

// newExporter creates a new Tiris exporter instance.
func newExporter(cfg *Config, logger *zap.Logger) (*tirisExporter, error) {
	tokenManager, err := NewTokenManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create token manager: %w", err)
	}

	return &tirisExporter{
		config:       cfg,
		logger:       logger,
		tokenManager: tokenManager,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}, nil
}

// start validates authentication by pre-fetching a token on startup.
func (e *tirisExporter) start(ctx context.Context, _ component.Host) error {
	e.logger.Info("Starting Tiris exporter",
		zap.String("endpoint", e.config.Endpoint),
		zap.String("account", e.config.SnowflakeAccount),
		zap.String("user", e.config.SnowflakeUser),
	)

	// Pre-fetch token to validate authentication setup
	_, err := e.tokenManager.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to obtain initial OAuth token: %w", err)
	}

	e.logger.Info("Successfully authenticated with Snowflake")
	return nil
}

// shutdown performs cleanup when the exporter stops.
func (e *tirisExporter) shutdown(_ context.Context) error {
	e.logger.Info("Shutting down Tiris exporter")
	return nil
}

// sendOTLP sends protobuf-encoded OTLP data to the Tiris backend with OAuth authentication.
func (e *tirisExporter) sendOTLP(ctx context.Context, endpoint string, body []byte) error {
	// Get valid OAuth token (cached or refreshed)
	token, err := e.tokenManager.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get OAuth token: %w", err)
	}

	// Construct full URL
	fullURL := e.config.Endpoint + endpoint

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set required headers
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Authorization", "Snowflake Token=\""+token+"\"")

	// Add custom headers from config
	for key, val := range e.config.Headers {
		if string(val) != "" {
			req.Header.Set(key, string(val))
		}
	}

	e.logger.Info("Sending OTLP request",
		zap.String("url", fullURL),
		zap.Int("body_size", len(body)),
	)

	// Send request
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, _ := io.ReadAll(resp.Body)

	e.logger.Info("OTLP response received",
		zap.Int("status_code", resp.StatusCode),
		zap.String("response_body", string(respBody)),
	)

	// OTLP specification: Always returns 200 OK, check partial_success in response body
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
