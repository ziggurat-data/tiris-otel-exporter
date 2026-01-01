package tirisexporter

import (
	"errors"

	"go.opentelemetry.io/collector/config/confighttp"
)

// Config defines configuration for the Tiris exporter.
type Config struct {
	confighttp.ClientConfig `mapstructure:",squash"` // Includes Endpoint, Timeout, Headers, etc.

	// Snowflake Account Identifier (e.g., "xo68546.eu-central-1")
	SnowflakeAccount string `mapstructure:"snowflake_account"`

	// Snowflake Username (e.g., "SHANGU")
	SnowflakeUser string `mapstructure:"snowflake_user"`

	// Path to RSA private key file (PEM format)
	PrivateKeyPath string `mapstructure:"private_key_path"`

	// Optional: Private key passphrase (if key is encrypted)
	PrivateKeyPassphrase string `mapstructure:"private_key_passphrase,omitempty"`

	// JWT Token Lifetime in minutes (default: 59, max: 59 per Snowflake)
	JWTLifetime int `mapstructure:"jwt_lifetime,omitempty"`

	// Token Refresh Buffer in minutes (default: 5)
	// Token will be refreshed this many minutes before expiry
	TokenRefreshBuffer int `mapstructure:"token_refresh_buffer,omitempty"`
}

// Validate checks if the exporter configuration is valid.
func (cfg *Config) Validate() error {
	if cfg.Endpoint == "" {
		return errors.New("endpoint is required")
	}
	if cfg.SnowflakeAccount == "" {
		return errors.New("snowflake_account is required")
	}
	if cfg.SnowflakeUser == "" {
		return errors.New("snowflake_user is required")
	}
	if cfg.PrivateKeyPath == "" {
		return errors.New("private_key_path is required")
	}

	// Set defaults
	if cfg.JWTLifetime == 0 {
		cfg.JWTLifetime = 59 // minutes (Snowflake max is 59)
	}
	if cfg.JWTLifetime > 59 {
		return errors.New("jwt_lifetime cannot exceed 59 minutes (Snowflake limitation)")
	}

	if cfg.TokenRefreshBuffer == 0 {
		cfg.TokenRefreshBuffer = 5 // minutes
	}

	return nil
}
