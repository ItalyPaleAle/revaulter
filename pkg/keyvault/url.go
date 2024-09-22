package keyvault

import (
	"strings"
)

// vaultUrl returns the URL for the Azure Key Vault
// Parameter vault can be one of:
// - The address of the vault, such as "https://<name>.vault.azure.net" (could be a different format if using different clouds or private endpoints)
// - The FQDN of the vault, such as "<name>.vault.azure.net" (or another domain if using different clouds or private endpoints)
// - Only the name of the vault, which will be formatted for "vault.azure.net"
func VaultUrl(vault string) string {
	// If there's a dot, assume it's either a full URL or a FQDN
	if strings.ContainsRune(vault, '.') {
		if !strings.HasPrefix(vault, "https://") {
			vault = "https://" + vault
		}
		return vault
	}

	return "https://" + vault + ".vault.azure.net"
}
