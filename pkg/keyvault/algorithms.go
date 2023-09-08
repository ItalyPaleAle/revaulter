package keyvault

import "github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

var supportedAlgorithms map[string]struct{}

func init() {
	enc := azkeys.PossibleEncryptionAlgorithmValues()
	sig := azkeys.PossibleSignatureAlgorithmValues()
	supportedAlgorithms = make(map[string]struct{}, len(enc)+len(sig))
	for _, alg := range enc {
		supportedAlgorithms[string(alg)] = struct{}{}
	}
	for _, alg := range sig {
		supportedAlgorithms[string(alg)] = struct{}{}
	}
}

// IsAlgorithmSupported returns true if the algorithm is supported for encryption or signature
func IsAlgorithmSupported(alg string) bool {
	_, ok := supportedAlgorithms[alg]
	return ok
}
