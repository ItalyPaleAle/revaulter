// Package integrity carries the web client integrity artifacts that get embedded into the server binary at release time
package integrity

import (
	_ "embed"
)

// Both files are populated by the release workflow before `go build`
// In dev builds they are empty / stub values and the server reports hasIntegrity=false
var (
	// ManifestBytes is the raw text manifest
	//go:embed manifest.txt
	ManifestBytes []byte
	// BundleBytes is the cosign keyless signing bundle
	//go:embed manifest.sigstore.json
	BundleBytes []byte
)

// HasManifest reports whether a real integrity manifest is embedded in this binary
// The stub files shipped for dev builds are either empty (manifest) or contain just `{}` (bundle)
func HasManifest() bool {
	if len(ManifestBytes) == 0 {
		return false
	}

	// The bundle stub is `{}` plus an optional trailing newline
	if len(BundleBytes) <= 3 {
		return false
	}

	return true
}
