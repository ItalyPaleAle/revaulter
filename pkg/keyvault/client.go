package keyvault

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azTracing "github.com/Azure/azure-sdk-for-go/sdk/azcore/tracing"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/tracing/azotel"
	"github.com/alphadose/haxmap"
	"github.com/italypaleale/revaulter/pkg/utils"
	sdkTrace "go.opentelemetry.io/otel/sdk/trace"
)

// Client is a client for Azure Key Vault
type Client interface {
	// Encrypt a message using a key stored in the Key Vault
	Encrypt(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationParameters) (*KeyVaultEncryptResponse, error)
	// Decrypt a message using a key stored in the Key Vault.
	Decrypt(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationParameters) (*KeyVaultDecryptResponse, error)
	// WrapKey wraps a key using the key-encryption-key stored in the Key Vault
	WrapKey(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationParameters) (*KeyVaultEncryptResponse, error)
	// UnwrapKey unwrap a wrapped key using the key-encryption-key stored in the Key Vault
	UnwrapKey(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationParameters) (*KeyVaultDecryptResponse, error)
	// Sign a message using a key stored in the Key Vault
	Sign(ctx context.Context, vault, keyName, keyVersion string, params azkeys.SignParameters) (*KeyVaultSignResponse, error)
	// Verify a signature using a key stored in the Key Vault
	Verify(ctx context.Context, vault, keyName, keyVersion string, params azkeys.VerifyParameters) (*KeyVaultVerifyResponse, error)
}

type ClientOptions struct {
	AccessToken string
	Expiration  time.Time
	Tracer      *sdkTrace.TracerProvider
}

// ClientFactory is the type for the NewClient function
type ClientFactory func(opts ClientOptions) Client

// NewClient returns a new Client object
func NewClient(opts ClientOptions) Client {
	c := &client{
		cred:    newTokenProvider(opts.AccessToken, opts.Expiration),
		clients: haxmap.New[string, *azkeys.Client](4),
	}

	if opts.Tracer != nil {
		c.tracer = azotel.NewTracingProvider(opts.Tracer, nil)
	}

	return c
}

type client struct {
	cred    tokenProvider
	clients *haxmap.Map[string, *azkeys.Client]

	// The default value is a no-op provider
	tracer azTracing.Provider
}

// Encrypt a message using a key stored in the Key Vault
func (c *client) Encrypt(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationParameters) (*KeyVaultEncryptResponse, error) {
	// Get the client
	client := c.getClientForVault(ctx, vault)
	if client == nil {
		return nil, errors.New("could not get Azure Key Vault client")
	}

	// Perform the operation
	res, err := client.Encrypt(ctx, keyName, keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("error from Azure Key Vault: %w", err)
	}
	if res.Result == nil || res.KID == nil {
		return nil, errors.New("response from Azure Key Vault is invalid")
	}

	return &KeyVaultEncryptResponse{
		keyVaultResponseBase: keyVaultResponseBase{
			keyID: string(*res.KID),
		},
		Data:  res.Result,
		Nonce: params.IV,
		Tag:   res.AuthenticationTag,
	}, nil
}

// Decrypt a message using a key stored in the Key Vault.
func (c *client) Decrypt(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationParameters) (*KeyVaultDecryptResponse, error) {
	// Get the client
	client := c.getClientForVault(ctx, vault)
	if client == nil {
		return nil, errors.New("could not get Azure Key Vault client")
	}

	// Perform the operation
	res, err := client.Decrypt(ctx, keyName, keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("error from Azure Key Vault: %w", err)
	}
	if res.Result == nil || res.KID == nil {
		return nil, errors.New("response from Azure Key Vault is invalid")
	}

	return &KeyVaultDecryptResponse{
		keyVaultResponseBase: keyVaultResponseBase{
			keyID: string(*res.KID),
		},
		Data: res.Result,
	}, nil
}

// WrapKey wraps a key using the key-encryption-key stored in the Key Vault
func (c *client) WrapKey(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationParameters) (*KeyVaultEncryptResponse, error) {
	// Get the client
	client := c.getClientForVault(ctx, vault)
	if client == nil {
		return nil, errors.New("could not get Azure Key Vault client")
	}

	// Perform the operation
	res, err := client.WrapKey(ctx, keyName, keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("error from Azure Key Vault: %w", err)
	}
	if res.Result == nil || res.KID == nil {
		return nil, errors.New("response from Azure Key Vault is invalid")
	}

	return &KeyVaultEncryptResponse{
		keyVaultResponseBase: keyVaultResponseBase{
			keyID: string(*res.KID),
		},
		Data:  res.Result,
		Nonce: params.IV,
		Tag:   res.AuthenticationTag,
	}, nil
}

// UnwrapKey unwrap a wrapped key using the key-encryption-key stored in the Key Vault
func (c *client) UnwrapKey(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationParameters) (*KeyVaultDecryptResponse, error) {
	// Get the client
	client := c.getClientForVault(ctx, vault)
	if client == nil {
		return nil, errors.New("could not get Azure Key Vault client")
	}

	// Perform the operation
	res, err := client.UnwrapKey(ctx, keyName, keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("error from Azure Key Vault: %w", err)
	}
	if res.Result == nil || res.KID == nil {
		return nil, errors.New("response from Azure Key Vault is invalid")
	}

	return &KeyVaultDecryptResponse{
		keyVaultResponseBase: keyVaultResponseBase{
			keyID: string(*res.KID),
		},
		Data: res.Result,
	}, nil
}

// Sign a message using a key stored in the Key Vault
func (c *client) Sign(ctx context.Context, vault, keyName, keyVersion string, params azkeys.SignParameters) (*KeyVaultSignResponse, error) {
	// Get the client
	client := c.getClientForVault(ctx, vault)
	if client == nil {
		return nil, errors.New("could not get Azure Key Vault client")
	}

	// Perform the operation
	res, err := client.Sign(ctx, keyName, keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("error from Azure Key Vault: %w", err)
	}
	if res.Result == nil || res.KID == nil {
		return nil, errors.New("response from Azure Key Vault is invalid")
	}

	return &KeyVaultSignResponse{
		keyVaultResponseBase: keyVaultResponseBase{
			keyID: string(*res.KID),
		},
		Data: res.Result,
	}, nil
}

// Verify a signature using a key stored in the Key Vault
func (c *client) Verify(ctx context.Context, vault, keyName, keyVersion string, params azkeys.VerifyParameters) (*KeyVaultVerifyResponse, error) {
	// Get the client
	client := c.getClientForVault(ctx, vault)
	if client == nil {
		return nil, errors.New("could not get Azure Key Vault client")
	}

	// Perform the operation
	res, err := client.Verify(ctx, keyName, keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("error from Azure Key Vault: %w", err)
	}
	if res.Value == nil {
		return nil, errors.New("response from Azure Key Vault is empty")
	}

	return &KeyVaultVerifyResponse{
		keyVaultResponseBase: keyVaultResponseBase{
			// Response from Azure Key Vault does not contain a key ID
			keyID: "",
		},
		Valid: *res.Value,
	}, nil
}

// vaultUrl returns the URL for the Azure Key Vault
// Parameter vault can be one of:
// - The address of the vault, such as "https://<name>.vault.azure.net" (could be a different format if using different clouds or private endpoints)
// - The FQDN of the vault, such as "<name>.vault.azure.net" (or another domain if using different clouds or private endpoints)
// - Only the name of the vault, which will be formatted for "vault.azure.net"
func (c client) vaultUrl(vault string) string {
	// If there's a dot, assume it's either a full URL or a FQDN
	if strings.ContainsRune(vault, '.') {
		if !strings.HasPrefix(vault, "https://") {
			vault = "https://" + vault
		}
		return vault
	}

	return "https://" + vault + ".vault.azure.net"
}

// getClientForVault returns the azkeys.Client object for the given vault
func (c *client) getClientForVault(ctx context.Context, vault string) *azkeys.Client {
	vaultUrl := c.vaultUrl(vault)

	client, _ := c.clients.GetOrCompute(vaultUrl, func() *azkeys.Client {
		client, err := azkeys.NewClient(vaultUrl, c.cred, &azkeys.ClientOptions{
			ClientOptions: policy.ClientOptions{
				Telemetry: policy.TelemetryOptions{
					Disabled: true,
				},
				TracingProvider: c.tracer,
			},
		})
		if err != nil {
			log := utils.LogFromContext(ctx)
			log.ErrorContext(ctx, "Failed to create azkeys.Client", slog.Any("error", err))
			return nil
		}
		return client
	})

	return client
}
