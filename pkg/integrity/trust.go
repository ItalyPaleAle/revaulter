package integrity

import (
	_ "embed"
)

// embeddedTrustRootJSON is Sigstore's Public Good trust root, fetched from the
// sigstore-go reference copy (trusted-root-public-good.json).
//
// It contains the long-lived infrastructure trust anchors for Sigstore:
//   - Fulcio root CA (verifies ephemeral signing certs were issued by Fulcio)
//   - Rekor public key (verifies the Signed Entry Timestamp proving a log entry exists)
//   - Certificate Transparency log keys (verify Fulcio logged the cert issuance)
//
// It does NOT contain any per-release signing key; cosign keyless uses ephemeral
// keypairs whose public half lives inside the signing bundle (bound to the
// release workflow's OIDC identity via Fulcio).
//
// Refresh this file periodically by running:
//
//	curl -o pkg/integrity/sigstore_trust_root.json \
//	  https://raw.githubusercontent.com/sigstore/sigstore-go/main/examples/trusted-root-public-good.json
//
// Old CLIs keep verifying existing releases; only very stale CLIs eventually
// need updating to verify NEW releases signed after a trust-root rotation.
//
//go:embed sigstore_trust_root.json
var embeddedTrustRootJSON []byte
