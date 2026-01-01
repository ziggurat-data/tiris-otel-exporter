package tirisexporter

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenManager handles Snowflake JWT generation and OAuth token exchange with caching.
type TokenManager struct {
	config     *Config
	privateKey *rsa.PrivateKey

	// Thread-safe token cache
	mu          sync.RWMutex
	accessToken string
	expiresAt   time.Time

	// HTTP client for OAuth requests
	httpClient *http.Client
}

// NewTokenManager creates a new token manager with the given configuration.
func NewTokenManager(cfg *Config) (*TokenManager, error) {
	privateKey, err := loadPrivateKey(cfg.PrivateKeyPath, cfg.PrivateKeyPassphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	return &TokenManager{
		config:     cfg,
		privateKey: privateKey,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// GetToken returns a valid OAuth access token, refreshing if needed (thread-safe).
func (tm *TokenManager) GetToken(ctx context.Context) (string, error) {
	// Fast path: read-lock check if token is still valid
	tm.mu.RLock()
	if time.Now().Add(time.Duration(tm.config.TokenRefreshBuffer) * time.Minute).Before(tm.expiresAt) {
		token := tm.accessToken
		tm.mu.RUnlock()
		return token, nil
	}
	tm.mu.RUnlock()

	// Slow path: write-lock and refresh token
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have refreshed)
	if time.Now().Add(time.Duration(tm.config.TokenRefreshBuffer) * time.Minute).Before(tm.expiresAt) {
		return tm.accessToken, nil
	}

	// Generate JWT
	jwtToken, err := tm.generateJWT()
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT: %w", err)
	}

	// Exchange JWT for OAuth token
	accessToken, expiresIn, err := tm.exchangeToken(ctx, jwtToken)
	if err != nil {
		return "", fmt.Errorf("failed to exchange token: %w", err)
	}

	// Update cache
	tm.accessToken = accessToken
	tm.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return accessToken, nil
}

// generateJWT creates a Snowflake-compatible JWT signed with the RSA private key.
func (tm *TokenManager) generateJWT() (string, error) {
	now := time.Now()

	// Snowflake-specific JWT claims format
	// See: https://docs.snowflake.com/en/developer-guide/sql-api/authenticating.html#using-key-pair-authentication
	//
	// For keypair JWT auth, the issuer format is:
	// ACCOUNT_IDENTIFIER.USER_NAME.SHA256:PUBLIC_KEY_FINGERPRINT
	//
	// Account identifier should be uppercase and use the account locator format
	// e.g., "GB93700" not "gb93700.eu-central-1"
	accountLocator := strings.ToUpper(strings.Split(tm.config.SnowflakeAccount, ".")[0])
	userName := strings.ToUpper(tm.config.SnowflakeUser)
	keyFingerprint := generateKeyFingerprint(tm.privateKey)

	// Full qualified issuer: ACCOUNT.USER.SHA256:FINGERPRINT
	issuer := fmt.Sprintf("%s.%s.SHA256:%s", accountLocator, userName, keyFingerprint)
	subject := fmt.Sprintf("%s.%s", accountLocator, userName)

	claims := jwt.MapClaims{
		"iss": issuer,       // Issuer: ACCOUNT.USER.SHA256:FINGERPRINT
		"sub": subject,      // Subject: ACCOUNT.USER
		"iat": now.Unix(),   // Issued at
		"exp": now.Add(time.Duration(tm.config.JWTLifetime) * time.Minute).Unix(), // Expiry
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign the token
	signedToken, err := token.SignedString(tm.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return signedToken, nil
}

// exchangeToken exchanges a JWT for an OAuth access token via Snowflake's token endpoint.
func (tm *TokenManager) exchangeToken(ctx context.Context, jwtToken string) (string, int, error) {
	// Use /oauth/token endpoint (not /oauth/token-request)
	tokenURL := fmt.Sprintf("https://%s.snowflakecomputing.com/oauth/token", tm.config.SnowflakeAccount)

	// Extract the SPCS ingress hostname from the endpoint for the scope
	// e.g., "https://foo.snowflakecomputing.app" -> "foo.snowflakecomputing.app"
	endpointHost := strings.TrimPrefix(tm.config.Endpoint, "https://")
	endpointHost = strings.TrimPrefix(endpointHost, "http://")
	endpointHost = strings.Split(endpointHost, "/")[0] // Remove any path

	// Prepare form data for SPCS token exchange
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	data.Set("assertion", jwtToken)
	data.Set("scope", endpointHost)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := tm.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read body
	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Snowflake returns the access token directly as a JWT string (not JSON wrapped)
	accessToken := strings.TrimSpace(string(bodyBytes))
	if accessToken == "" {
		return "", 0, errors.New("token exchange response is empty")
	}

	// The token itself is a JWT - we can decode it to get the expiration time
	// For now, use a default expiration of 1 hour (3600 seconds) which is typical for SPCS tokens
	expiresIn := 3600

	return accessToken, expiresIn, nil
}

// loadPrivateKey loads an RSA private key from a PEM file, with optional passphrase decryption.
func loadPrivateKey(path, passphrase string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block from key file")
	}

	var keyDER []byte

	if passphrase != "" {
		// Decrypt encrypted PEM block
		keyDER, err = x509.DecryptPEMBlock(block, []byte(passphrase)) //nolint:staticcheck
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt key with passphrase: %w", err)
		}
	} else {
		keyDER = block.Bytes
	}

	// Try parsing as PKCS#1 first
	if key, err := x509.ParsePKCS1PrivateKey(keyDER); err == nil {
		return key, nil
	}

	// Try parsing as PKCS#8
	keyInterface, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key (tried PKCS#1 and PKCS#8): %w", err)
	}

	rsaKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an RSA key")
	}

	return rsaKey, nil
}

// generateKeyFingerprint generates a SHA256 fingerprint of the RSA public key.
// This is used as the "kid" (key ID) in the JWT header for Snowflake authentication.
func generateKeyFingerprint(privateKey *rsa.PrivateKey) string {
	// Extract public key and convert to DER format
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		// Fallback to empty string (shouldn't happen)
		return ""
	}

	// Calculate SHA256 hash
	hash := sha256.Sum256(publicKeyDER)

	// Return base64-encoded hash
	return base64.StdEncoding.EncodeToString(hash[:])
}
