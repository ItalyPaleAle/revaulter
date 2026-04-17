package integrity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
)

// Identity policy for Revaulter's release workflow
// The signer must be an ephemeral cert issued by Fulcio via GitHub Actions OIDC
// with a SAN matching the release workflow for this repo (on tag or main-branch pushes)
const expectedIssuer = "https://token.actions.githubusercontent.com"

// expectedSANRegex is the regex the signer's Subject Alternative Name must match
// Built once at package init from buildinfo.RepoURL (set via ldflags at release time)
// so the CLI accepts signatures only from its own build's source repo
var expectedSANRegex string

func init() {
	expectedSANRegex = `^` + regexp.QuoteMeta(buildinfo.RepoURL) + `/\.github/workflows/release\.yaml@refs/(tags/v.+|heads/main)$`
}

// Default public-good Rekor base URL used by the live fallback
const defaultRekorBaseURL = "https://rekor.sigstore.dev"

// VerifyBundle verifies a cosign keyless signing bundle over manifestBytes
// It checks three things:
//  1. The signature covers the SHA-256 of manifestBytes
//  2. The signing cert chains to the embedded Fulcio root and its SAN matches the release-workflow identity
//  3. The bundle's Rekor transparency-log entry is valid against the embedded Rekor public key
//
// On success the returned VerificationResult includes the verified identity for callers that want to display it
func VerifyBundle(manifestBytes, bundleBytes []byte) (*verify.VerificationResult, error) {
	if len(manifestBytes) == 0 {
		return nil, errors.New("manifest is empty")
	}
	if len(bundleBytes) == 0 {
		return nil, errors.New("bundle is empty")
	}

	trustedRoot, err := loadTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("load embedded trust root: %w", err)
	}

	b := &bundle.Bundle{}
	err = b.UnmarshalJSON(bundleBytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing bundle: %w", err)
	}

	return verifyEntity(trustedRoot, b, manifestBytes)
}

// VerifyViaRekor is the fallback: if the server returns no bundle (or the inline bundle fails verification)
// the CLI can still recover by querying the Rekor transparency log live for an entry
// whose artifact digest equals sha256(manifestBytes), then reconstructing a bundle
// from that entry and verifying it against the same embedded trust roots and identity policy
// ctx controls the HTTP timeout; rekorBaseURL can be empty to use the default public-good instance
func VerifyViaRekor(ctx context.Context, manifestBytes []byte, rekorBaseURL string) (*verify.VerificationResult, error) {
	if len(manifestBytes) == 0 {
		return nil, errors.New("manifest is empty")
	}
	if rekorBaseURL == "" {
		rekorBaseURL = defaultRekorBaseURL
	}

	trustedRoot, err := loadTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("load embedded trust root: %w", err)
	}

	digest := sha256.Sum256(manifestBytes)
	hexDigest := hex.EncodeToString(digest[:])

	uuids, err := rekorSearchByHash(ctx, rekorBaseURL, hexDigest)
	if err != nil {
		return nil, fmt.Errorf("rekor search by hash: %w", err)
	}
	if len(uuids) == 0 {
		return nil, errors.New("no rekor entries found for manifest digest")
	}

	// Try each returned UUID until one verifies
	// Older duplicates can exist; the first to match the identity policy wins
	var lastErr error
	for _, uuid := range uuids {
		b, err := rekorEntryAsBundle(ctx, rekorBaseURL, uuid, digest[:])
		if err != nil {
			lastErr = fmt.Errorf("uuid=%s: %w", uuid, err)
			continue
		}
		result, err := verifyEntity(trustedRoot, b, manifestBytes)
		if err != nil {
			lastErr = fmt.Errorf("uuid=%s: %w", uuid, err)
			continue
		}
		return result, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no rekor entries matched identity policy")
	}
	return nil, lastErr
}

// verifyEntity is the shared post-parse path used by both primary and Rekor fallback
// It runs sigstore-go's verifier with the embedded identity policy
func verifyEntity(trustedRoot *root.TrustedRoot, b *bundle.Bundle, manifestBytes []byte) (*verify.VerificationResult, error) {
	verifier, err := verify.NewVerifier(trustedRoot,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("build verifier: %w", err)
	}

	certID, err := verify.NewShortCertificateIdentity(expectedIssuer, "", "", expectedSANRegex)
	if err != nil {
		return nil, fmt.Errorf("build identity policy: %w", err)
	}

	digest := sha256.Sum256(manifestBytes)
	result, err := verifier.Verify(b, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digest[:]),
		verify.WithCertificateIdentity(certID),
	))
	if err != nil {
		return nil, fmt.Errorf("verify signature: %w", err)
	}
	return result, nil
}

// loadTrustedRoot parses the embedded Sigstore public-good trust root JSON
func loadTrustedRoot() (*root.TrustedRoot, error) {
	return root.NewTrustedRootFromJSON(embeddedTrustRootJSON)
}

// --- Rekor client ---

// rekorSearchByHash queries POST /api/v1/index/retrieve to find entries with a given artifact digest
// Returns a list of entry UUIDs
func rekorSearchByHash(ctx context.Context, baseURL, hexSHA256 string) ([]string, error) {
	body := map[string]string{"hash": "sha256:" + hexSHA256}
	var uuids []string
	err := rekorJSON(ctx, http.MethodPost, baseURL+"/api/v1/index/retrieve", body, &uuids)
	if err != nil {
		return nil, err
	}
	return uuids, nil
}

// rekorEntryAsBundle fetches a specific Rekor entry and converts it into a sigstore-go Bundle
// The artifactDigest is the SHA-256 of the manifest; the returned bundle binds the recovered
// signature and cert to this digest via its messageSignature content
func rekorEntryAsBundle(ctx context.Context, baseURL, uuid string, artifactDigest []byte) (*bundle.Bundle, error) {
	// GET /api/v1/log/entries/{uuid} returns a map[uuid]entry
	respMap := map[string]rekorLogEntry{}
	err := rekorJSON(ctx, http.MethodGet, baseURL+"/api/v1/log/entries/"+uuid, nil, &respMap)
	if err != nil {
		return nil, err
	}
	entry, ok := respMap[uuid]
	if !ok {
		// Some Rekor deployments return a single-key map keyed by the resolved UUID
		for _, v := range respMap {
			entry = v
			ok = true
			break
		}
	}
	if !ok {
		return nil, errors.New("empty rekor entry response")
	}

	// Decode the canonicalized body (base64 → raw JSON hashedrekord)
	bodyBytes, err := base64.StdEncoding.DecodeString(entry.Body)
	if err != nil {
		return nil, fmt.Errorf("decode entry body: %w", err)
	}

	// Parse the hashedrekord to get the signature and leaf cert
	sig, certDER, err := parseHashedRekord(bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse hashedrekord: %w", err)
	}

	// Decode the SET (base64) and the logID (hex)
	set, err := base64.StdEncoding.DecodeString(entry.Verification.SignedEntryTimestamp)
	if err != nil {
		return nil, fmt.Errorf("decode SET: %w", err)
	}
	logIDBytes, err := hex.DecodeString(entry.LogID)
	if err != nil {
		return nil, fmt.Errorf("decode logID: %w", err)
	}

	// Decode the inclusion proof fields
	proof, err := entry.Verification.InclusionProof.toProto()
	if err != nil {
		return nil, fmt.Errorf("decode inclusion proof: %w", err)
	}

	pbBundle, err := assembleBundleProto(artifactDigest, sig, certDER, logIDBytes, entry.LogIndex, entry.IntegratedTime, set, proof, bodyBytes)
	if err != nil {
		return nil, err
	}

	return bundle.NewBundle(pbBundle)
}

// parseHashedRekord decodes a hashedrekord v0.0.1 body and returns the raw signature bytes and the DER-encoded leaf certificate
func parseHashedRekord(bodyJSON []byte) (sig, certDER []byte, err error) {
	var wrap struct {
		Kind       string          `json:"kind"`
		APIVersion string          `json:"apiVersion"`
		Spec       json.RawMessage `json:"spec"`
	}
	err = json.Unmarshal(bodyJSON, &wrap)
	if err != nil {
		return nil, nil, fmt.Errorf("unwrap entry: %w", err)
	}
	if wrap.Kind != "hashedrekord" {
		return nil, nil, fmt.Errorf("unsupported rekor entry kind %q (expected hashedrekord)", wrap.Kind)
	}

	var spec struct {
		Signature struct {
			Content   string `json:"content"`
			PublicKey struct {
				Content string `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	}
	err = json.Unmarshal(wrap.Spec, &spec)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal spec: %w", err)
	}

	sig, err = base64.StdEncoding.DecodeString(spec.Signature.Content)
	if err != nil {
		return nil, nil, fmt.Errorf("decode signature: %w", err)
	}
	// publicKey.content is base64-encoded PEM of the leaf cert for keyless flows
	pemBytes, err := base64.StdEncoding.DecodeString(spec.Signature.PublicKey.Content)
	if err != nil {
		return nil, nil, fmt.Errorf("decode publicKey.content: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, errors.New("publicKey.content is not a PEM CERTIFICATE")
	}
	// Validate it parses as a cert; we keep the DER bytes for the bundle
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse leaf cert: %w", err)
	}
	return sig, block.Bytes, nil
}

// assembleBundleProto builds a v0.3 Sigstore bundle from the pieces recovered from a Rekor entry
func assembleBundleProto(
	artifactDigest, sig, certDER, logIDBytes []byte,
	logIndex, integratedTime int64,
	set []byte,
	proof *protorekor.InclusionProof,
	canonicalizedBody []byte,
) (*protobundle.Bundle, error) {
	if len(artifactDigest) != sha256.Size {
		return nil, fmt.Errorf("expected sha256 digest length %d, got %d", sha256.Size, len(artifactDigest))
	}

	return &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: certDER},
			},
			TlogEntries: []*protorekor.TransparencyLogEntry{
				{
					LogIndex: logIndex,
					LogId: &protocommon.LogId{
						KeyId: logIDBytes,
					},
					KindVersion: &protorekor.KindVersion{
						Kind:    "hashedrekord",
						Version: "0.0.1",
					},
					IntegratedTime: integratedTime,
					InclusionPromise: &protorekor.InclusionPromise{
						SignedEntryTimestamp: set,
					},
					InclusionProof:    proof,
					CanonicalizedBody: canonicalizedBody,
				},
			},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    artifactDigest,
				},
				Signature: sig,
			},
		},
	}, nil
}

// --- Rekor response types ---

type rekorLogEntry struct {
	Body           string            `json:"body"`
	IntegratedTime int64             `json:"integratedTime"`
	LogID          string            `json:"logID"`
	LogIndex       int64             `json:"logIndex"`
	Verification   rekorVerification `json:"verification"`
}

type rekorVerification struct {
	SignedEntryTimestamp string              `json:"signedEntryTimestamp"`
	InclusionProof       rekorInclusionProof `json:"inclusionProof"`
}

type rekorInclusionProof struct {
	LogIndex   int64    `json:"logIndex"`
	RootHash   string   `json:"rootHash"`
	TreeSize   int64    `json:"treeSize"`
	Hashes     []string `json:"hashes"`
	Checkpoint string   `json:"checkpoint"`
}

func (p rekorInclusionProof) toProto() (*protorekor.InclusionProof, error) {
	rootHash, err := hex.DecodeString(p.RootHash)
	if err != nil {
		return nil, fmt.Errorf("decode rootHash: %w", err)
	}
	hashes := make([][]byte, 0, len(p.Hashes))
	for i, h := range p.Hashes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("decode hashes[%d]: %w", i, err)
		}
		hashes = append(hashes, b)
	}
	return &protorekor.InclusionProof{
		LogIndex: p.LogIndex,
		RootHash: rootHash,
		TreeSize: p.TreeSize,
		Hashes:   hashes,
		Checkpoint: &protorekor.Checkpoint{
			Envelope: p.Checkpoint,
		},
	}, nil
}

// rekorJSON issues a JSON request/response round-trip to Rekor with a reasonable default timeout
func rekorJSON(ctx context.Context, method, url string, reqBody, outBody any) error {
	var body io.Reader
	if reqBody != nil {
		buf, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(buf)
	}

	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, method, url, body)
	if err != nil {
		return err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return fmt.Errorf("rekor %s %s: status %d: %s", method, url, res.StatusCode, string(b))
	}
	if outBody == nil {
		return nil
	}
	return json.NewDecoder(res.Body).Decode(outBody)
}
