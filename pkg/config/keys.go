package config

const (
	KeyAllowedIps             = "allowedIps"
	KeyAzureClientId          = "azureClientId"
	KeyAzureTenantId          = "azureTenantId"
	KeyBaseUrl                = "baseUrl"
	KeyBind                   = "bind"
	KeyCookieEncryptionKey    = "cookieEncryptionKey"
	KeyEnableMetrics          = "enableMetrics"
	KeyLogLevel               = "logLevel"
	KeyMetricsBind            = "metricsBind"
	KeyMetricsPort            = "metricsPort"
	KeyOrigins                = "origins"
	KeyPort                   = "port"
	KeyRequestTimeout         = "requestTimeout"
	KeyRequestKey             = "requestKey"
	KeySessionTimeout         = "sessionTimeout"
	KeyTLSPath                = "tlsPath"
	KeyTLSCertPEM             = "tlsCertPEM"
	KeyTLSKeyPEM              = "tlsKeyPEM"
	KeyTokenSigningKey        = "tokenSigningKey"
	KeyTrustedRequestIdHeader = "trustedRequestIdHeader"
	KeyWebhookFormat          = "webhookFormat"
	KeyWebhookKey             = "webhookKey"
	KeyWebhookUrl             = "webhookUrl"

	// Keys starting with "dev." are undocumented and meant for development only
	KeyDevClientProxyServer = "dev.clientProxyServer"

	// Key starting with "internal." are set by the app at startup
	KeyInternalTokenSigningKey     = "internal.tokenSigningKey"
	KeyInternalCookieEncryptionKey = "internal.cookieEncryptionKey"
	KeyInternalCookieSigningKey    = "internal.cookieSigningKey"
)
