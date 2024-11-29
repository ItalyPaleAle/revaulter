package config

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/italypaleale/revaulter/pkg/keyvault"
)

// Config is the struct containing configuration
type Config struct {
	// Client ID of the Azure AD application
	// +required
	AzureClientId string `env:"AZURECLIENTID" yaml:"azureClientId"`

	// Tenant ID of the Azure AD application.
	// +required
	AzureTenantId string `env:"AZURETENANTID" yaml:"azureTenantId"`

	// Client secret of the Azure AD application, for using confidential clients.
	// This is optional, but recommended when not using Federated Identity Credentials.
	AzureClientSecret string `env:"AZURECLIENTSECRET" yaml:"azureClientSecret"`

	// Enables the usage of Federated Identity Credentials to obtain assertions for confidential clients for Azure AD applications.
	// This is an alternative to using client secrets, when the application is running in Azure in an environment that supports Managed Identity, or in an environment that supports Workload Identity Federation with Azure AD.
	// Currently, these values are supported:
	//
	// - `ManagedIdentity`: uses a system-assigned managed identity
	// - `ManagedIdentity=client-id`: uses a user-assigned managed identity with client id "client-id" (e.g. "ManagedIdentity=00000000-0000-0000-0000-000000000000")
	// - `WorkloadIdentity`: uses workload identity, e.g. for Kubernetes
	AzureFederatedIdentity string `env:"AZUREFEDERATEDIDENTITY" yaml:"azureFederatedIdentity"`

	// Endpoint of the webhook, where notifications are sent to.
	// +required
	WebhookUrl string `env:"WEBHOOKURL" yaml:"webhookUrl"`

	// The format for the webhook.
	// Currently, these values are supported:
	//
	// - `plain`: sends a webhook with content type `text/plain`, where the request's body is the entire message
	// - `slack`: for usage with Slack or Slack-compatible endpoints
	// - `discord`: for usage with Discord (sends Slack-compatible messages)
	// +default "plain"
	WebhookFormat string `env:"WEBHOOKFORMAT" yaml:"webhookFormat"`

	// Value for the Authorization header send with the webhook request. Set this if your webhook requires it.
	WebhookKey string `env:"WEBHOOKKEY" yaml:"webhookKey"`

	// The URL your application can be reached at. This is used in the links that are sent in webhook notifications.
	// This is optional, but recommended.
	// +default `https://localhost:<port>` if TLS is enabled, or `http://localhost:<port>` otherwise
	BaseUrl string `env:"BASEURL" yaml:"baseUrl"`

	// Port to bind to.
	// +default 8080
	Port int `env:"PORT" yaml:"port"`

	// Address/interface to bind to.
	// +default "0.0.0.0"
	Bind string `env:"BIND" yaml:"bind"`

	// Path where to load TLS certificates from. Within the folder, the files must be named `tls-cert.pem` and `tls-key.pem`. Revaulter watches for changes in this folder and automatically reloads the TLS certificates when they're updated.
	// If empty, certificates are loaded from the same folder where the loaded `config.yaml` is located.
	// +default the same folder as the `config.yaml` file
	TLSPath string `env:"TLSPATH" yaml:"tlsPath"`

	// Full, PEM-encoded TLS certificate. Using `tlsCertPEM` and `tlsKeyPEM` is an alternative method of passing TLS certificates than using `tlsPath`.
	TLSCertPEM string `env:"TLSCERTPEM" yaml:"tlsCertPEM"`

	// Full, PEM-encoded TLS key. Using `tlsCertPEM` and `tlsKeyPEM` is an alternative method of passing TLS certificates than using `tlsPath`.
	TLSKeyPEM string `env:"TLSKEYPEM" yaml:"tlsKeyPEM"`

	// If set, allows connections to the APIs only from the IPs or ranges set here. You can set individual IP addresses (IPv4 or IPv6) or ranges in the CIDR notation, and you can add multiple values separated by commas. For example, to allow connections from localhost and IPs in the `10.x.x.x` range only, set this to: `127.0.0.1,10.0.0.0/8`.
	// Note that this value is used to restrict connections to the `/request` endpoints only. It does not restrict the endpoints used by administrators to confirm (or deny) requests.
	AllowedIPs []string `env:"ALLOWEDIPS" yaml:"allowedIps"`

	// If set, clients need to provide this shared key in calls made to the `/request` endpoints, in the `Authorization` header.
	// Note that this option only applies to calls to the `/request` endpoints. It does not apply to the endpoints used by administrators to confirm (or deny) requests.
	RequestKey string `env:"REQUESTKEY" yaml:"requestKey"`

	// If set, allows requests targeting only the Azure Key Vaults named in the list.
	// Values can be formatted as:
	//
	// - The address of the vault, such as "https://<name>.vault.azure.net" (could be a different format if using different clouds or private endpoints)
	// - The FQDN of the vault, such as "<name>.vault.azure.net" (or another domain if using different clouds or private endpoints)
	// - Only the name of the vault, which will be formatted for "vault.azure.net"
	AllowedVaults []string `env:"ALLOWEDVAULTS" yaml:"allowedVaults"`

	// Lists of origins that are allowed for CORS. This should be a list of all URLs admins can access Revaulter at. Alternatively, set this to `*` to allow any origin (not recommended).
	// +default equal to the value of `baseUrl`
	Origins []string `env:"ORIGINS" yaml:"origins"`

	// Timeout for sessions before having to authenticate again, as a Go duration. This cannot be more than 1 hour.
	// +default 5m
	SessionTimeout time.Duration `env:"SESSIONTIMEOUT" yaml:"sessionTimeout"`

	// Default timeout for wrap and unwrap requests, as a Go duration. This is the default value, and can be overridden in each request.
	// +default 5m
	RequestTimeout time.Duration `env:"REQUESTTIMEOUT" yaml:"requestTimeout"`

	// String with the name of a header (or multiple, comma-separated values) to trust as containing the client IP. This is usually necessary when Vault is served through a proxy service and/or CDN.
	// This option should not be set if the application is exposed directly, without a proxy or CDN.
	// Common values include:
	//
	// - `X-Forwarded-For,X-Real-Ip`: `X-Forwarded-For` is the [de-facto standard](https://http.dev/x-forwarded-for) set by proxies; some set `X-Real-Ip`
	// - `CF-Connecting-IP`: when the application is served by a [Cloudflare CDN](https://developers.cloudflare.com/fundamentals/reference/http-request-headers/#cf-connecting-ip)
	TrustedForwardedIPHeader string `env:"TRUSTEDFORWARDEDIPHEADER" yaml:"trustedForwardedIPHeader"`

	// Enable metrics collection.
	// Metrics can then be exposed via a Prometheus-compatible endpoint by enabling `metricsServerEnabled`.
	// Alternatively, metrics can be sent to an OpenTelemetry Collector; see `metricsOtelCollectorEndpoint`.
	// +default false
	EnableMetrics bool `env:"ENABLEMETRICS" yaml:"enableMetrics"`

	// Enable the metrics server, which exposes a Prometheus-compatible endpoint `/metrics`.
	// Metrics must be enabled for this to be effective
	// +default false
	MetricsServerEnabled bool `env:"METRICSSERVERENABLED" yaml:"metricsServerEnabled"`

	// Port for the metrics server to bind to.
	// +default 2112
	MetricsServerPort int `env:"METRICSSERVERPORT" yaml:"metricsServerPort"`

	// Address/interface for the metrics server to bind to.
	// +default "0.0.0.0"
	MetricsServerBind string `env:"METRICSSERVERBIND" yaml:"metricsServerBind"`

	// OpenTelemetry Collector endpoint for sending metrics, for example: `<http(s)-or-grpc(s)>://<otel-collector-address>:<otel-collector-port>/v1/metrics`
	// If metrics are enabled and `metricsOtelCollectorEndpoint` is set, metrics are sent to the collector
	// This value can also be set using the environmental variables `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` ("/v1/metrics" is appended for HTTP), and optionally `OTEL_EXPORTER_OTLP_PROTOCOL` ("http/protobuf", the default, or "grpc")
	MetricsOtelCollectorEndpoint string `env:"METRICSOTELCOLLECTORENDPOINT" yaml:"metricsOtelCollectorEndpoint"`

	// If true, calls to the healthcheck endpoint (`/healthz`) are not included in the logs.
	// +default false
	OmitHealthCheckLogs bool `env:"OMITHEALTHCHECKLOGS" yaml:"omitHealthCheckLogs"`

	// String used as key to sign state tokens. If left empty, it will be randomly generated every time the app starts (recommended, unless you need user sessions to persist after the application is restarted).
	// +default randomly-generated when the application starts
	TokenSigningKey string `env:"TOKENSIGNINGKEY" yaml:"tokenSigningKey"`

	// String used as key to encrypt cookies. If left empty, it will be randomly generated every time the app starts (recommended, unless you need user sessions to persist after the application is restarted).
	// +default randomly-generated when the application starts
	CookieEncryptionKey string `env:"COOKIEENCRYPTIONKEY" yaml:"cookieEncryptionKey"`

	// String with the name of a header to trust as ID of each request. The ID is included in logs and in responses as `X-Request-ID` header.
	// Common values can include:
	//
	// - `X-Request-ID`: a [de-facto standard](https://http.dev/x-request-id ) that's vendor agnostic
	// - `CF-Ray`: when the application is served by a [Cloudflare CDN](https://developers.cloudflare.com/fundamentals/get-started/reference/cloudflare-ray-id/)
	//
	// If this option is empty, or if it contains the name of a header that is not found in an incoming request, a random UUID is generated as request ID.
	TrustedRequestIdHeader string `env:"TRUSTEDREQUESTIDHEADER" yaml:"trustedRequestIdHeader"`

	// If true, forces all cookies to be set with the "secure" option, so they are only sent by clients on HTTPS requests.
	// When false (the default), cookies are set as "secure" only if the current request being served is using HTTPS.
	// When Revaulter is running behind a proxy that performs TLS termination, this option should normally be set to true.
	// +default false
	ForceSecureCookies bool `env:"FORCESECURECOOKIES" yaml:"forceSecureCookies"`

	// Controls log level and verbosity. Supported values: `debug`, `info` (default), `warn`, `error`.
	// +default "info"
	LogLevel string `env:"LOGLEVEL" yaml:"logLevel"`

	// If true, emits logs formatted as JSON, otherwise uses a text-based structured log format.
	// +default false if a TTY is attached (e.g. in development); true otherwise.
	LogAsJSON bool `env:"LOGASJSON" yaml:"logAsJson"`

	// OpenTelemetry Collector endpoint for sending logs, for example: `<http(s)>://<otel-collector-address>:<otel-collector-port>/v1/logs`.
	// If configured,logs are sent to the collector at the given address.
	// This value can also be set using the environmental variables `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` ("/v1/logs" is appended for HTTP), and optionally `OTEL_EXPORTER_OTLP_PROTOCOL` ("http/protobuf", the default, or "grpc").
	LogsOtelCollectorEndpoint string `env:"LOGSOTELCOLLECTORENDPOINT" yaml:"logsOtelCollectorEndpoint"`

	// If true, enables tracing with OpenTelemetry.
	// Traces can be sent to an OpenTelemetry Collector or Zipkin server.
	// If tracing is enabled, one of `tracingOtelCollectorEndpoint` or `tracingZipkinEndpoint` is required.
	// +default false
	EnableTracing bool `env:"ENABLETRACING" yaml:"enableTracing"`

	// Sampling rate for traces, as a float.
	// The default value is 1, sampling all requests.
	// +default 1
	TracingSampling float64 `env:"TRACINGSAMPLING" yaml:"tracingSampling"`

	// OpenTelemetry Collector endpoint for sending traces, for example: `<http(s)-or-grpc(s)>://<otel-collector-address>:<otel-collector-port>/v1/traces`.
	// If tracing is enabled, one of `tracingOtelCollectorEndpoint` or `tracingZipkinEndpoint` is required.
	// This value can also be set using the environmental variables `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` ("/v1/traces" is appended for HTTP), and optionally `OTEL_EXPORTER_OTLP_PROTOCOL` ("http/protobuf", the default, or "grpc").
	TracingOtelCollectorEndpoint string `env:"TRACINGOTELCOLLECTORENDPOINT" yaml:"tracingOtelCollectorEndpoint"`

	// Zipkin endpoint for sending traces, for example: `http://<zipkin-address>:<zipkin-port>/api/v2/spans`.
	// If tracing is enabled, one of `tracingOtelCollectorEndpoint` or `tracingZipkinEndpoint` is required.
	TracingZipkinEndpoint string `env:"TRACINGZIPKINENDPOINT" yaml:"tracingZipkinEndpoint"`

	// Dev is meant for development only; it's undocumented
	Dev Dev `yaml:"-"`

	// internal keys
	internal internal `yaml:"-"`
}

// Dev includes options using during development only
type Dev struct {
	ClientProxyServer string
}

// Internal properties
type internal struct {
	instanceID                string
	configFileLoaded          string // Path to the config file that was loaded
	tokenSigningKeyParsed     []byte
	cookieEncryptionKeyParsed jwk.Key
	cookieSigningKeyParsed    jwk.Key
}

// GetTokenSigningKey returns the (parsed) token signing key
func (c Config) GetTokenSigningKey() []byte {
	return c.internal.tokenSigningKeyParsed
}

// GetCookieEncryptionKey returns the (parsed) cookie encryption key
func (c Config) GetCookieEncryptionKey() jwk.Key {
	return c.internal.cookieEncryptionKeyParsed
}

// GetCookieSigningKey returns the (parsed) cookie signing key
func (c Config) GetCookieSigningKey() jwk.Key {
	return c.internal.cookieSigningKeyParsed
}

// GetLoadedConfigPath returns the path to the config file that was loaded
func (c Config) GetLoadedConfigPath() string {
	return c.internal.configFileLoaded
}

// SetLoadedConfigPath sets the path to the config file that was loaded
func (c *Config) SetLoadedConfigPath(filePath string) {
	c.internal.configFileLoaded = filePath
}

// GetInstanceID returns the instance ID.
func (c Config) GetInstanceID() string {
	return c.internal.instanceID
}

// Validates the configuration and performs some sanitization
func (c *Config) Validate(logger *slog.Logger) error {
	// Check required variables
	if c.AzureClientId == "" {
		return errors.New("config entry key 'azureClientId' missing")
	}
	if c.AzureTenantId == "" {
		return errors.New("config entry key 'azureTenantId' missing")
	}
	if c.WebhookUrl == "" {
		return errors.New("config entry key 'webhookUrl' missing")
	}

	// Check for invalid values
	if c.SessionTimeout < time.Second || c.SessionTimeout > time.Hour {
		return errors.New("config entry key 'sessionTimeout' is invalid: must be between 1s and 1h")
	}
	if c.RequestTimeout < time.Second {
		return errors.New("config entry key 'requestTimeout' is invalid: must be greater than 1s")
	}
	if c.AzureClientSecret != "" && c.AzureFederatedIdentity != "" {
		return errors.New("cannot specify 'azureClientSecret' in config when 'azureFederatedIdentity' is configured")
	}

	// Format URLs in the Key Vault allowlist
	for i := range c.AllowedVaults {
		c.AllowedVaults[i] = keyvault.VaultUrl(c.AllowedVaults[i])
	}

	// Show warnings if needed
	if logger != nil {
		if c.AzureClientSecret == "" && c.AzureFederatedIdentity == "" {
			logger.Warn(`Revaulter is running without an 'azureClientSecret' in the configuration, which requires using public clients ("mobile and desktop applications"). Configuring the Revaulter Entra ID (Azure AD) application as a confidential client ("web applications") and using either a client secret or Federated Identity is recommended for security.`)
		}
	}

	return nil
}

// SetTokenSigningKey parses the token signing key.
// If it's empty, will generate a new one.
func (c *Config) SetTokenSigningKey(logger *slog.Logger) (err error) {
	b := []byte(c.TokenSigningKey)
	if len(b) == 0 {
		if logger != nil {
			logger.Info("No 'tokenSigningKey' found in the configuration: a random one will be generated")
		}

		c.internal.tokenSigningKeyParsed = make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, c.internal.tokenSigningKeyParsed)
		if err != nil {
			return fmt.Errorf("failed to generate random bytes: %w", err)
		}
		return nil
	}

	// Compute a HMAC to ensure the key is 256-bit long
	h := hmac.New(crypto.SHA256.New, b)
	h.Write([]byte("revaulter-token-signing-key"))
	c.internal.tokenSigningKeyParsed = h.Sum(nil)

	return nil
}

// SetCookieKeys sets the cookie encryption and signing keys.
func (c *Config) SetCookieKeys(logger *slog.Logger) (err error) {
	// If we have cookieEncryptionKey set, derive the keys from that
	// Otherwise, generate the keys randomly
	var (
		// Cookie Encryption Key, 128-bit (for AES-KW)
		cekRaw []byte
		// Cookie Signing Key, 256-bit (for HMAC-SHA256)
		cskRaw []byte
	)
	if c.CookieEncryptionKey != "" {
		h := hmac.New(crypto.SHA384.New, []byte(c.CookieEncryptionKey))
		h.Write([]byte("revaulter-cookie-keys"))
		sum := h.Sum(nil)
		cekRaw = sum[0:16]
		cskRaw = sum[16:]
	} else {
		if logger != nil {
			logger.Info("No 'cookieEncryptionKey' found in the configuration: a random one will be generated")
		}

		cekRaw = make([]byte, 16)
		_, err = io.ReadFull(rand.Reader, cekRaw)
		if err != nil {
			return fmt.Errorf("failed to generate random cookieEncryptionKey: %w", err)
		}

		cskRaw = make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, cekRaw)
		if err != nil {
			return fmt.Errorf("failed to generate random cookieSigningKey: %w", err)
		}
	}

	// Calculate the key ID
	kid := computeKeyId(cskRaw)

	// Import the keys as JWKs
	c.internal.cookieEncryptionKeyParsed, err = jwk.FromRaw(cekRaw)
	if err != nil {
		return fmt.Errorf("failed to import cookieEncryptionKey as jwk.Key: %w", err)
	}
	_ = c.internal.cookieEncryptionKeyParsed.Set("kid", kid)

	c.internal.cookieSigningKeyParsed, err = jwk.FromRaw(cskRaw)
	if err != nil {
		return fmt.Errorf("failed to import cookieSigningKey as jwk.Key: %w", err)
	}
	_ = c.internal.cookieSigningKeyParsed.Set("kid", kid)

	return nil
}

// String implements fmt.Stringer and is used for debugging
// Returns the entire configuration as JSON
func (c Config) String() string {
	enc, _ := json.Marshal(c)
	return string(enc)
}

// Returns the key ID from a key
func computeKeyId(k []byte) string {
	h := sha256.Sum256(k)
	return base64.RawURLEncoding.EncodeToString(h[0:12])
}
