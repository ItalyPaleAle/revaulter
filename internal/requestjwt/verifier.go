package requestjwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jwx-go/jwkfetch/v4"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/httprc/v3/errsink"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"golang.org/x/sync/singleflight"
)

const (
	// Maximum size of an OIDC discovery document
	maxDiscoveryDocumentSize = 1 << 20 // 1MB

	// Default min time between forced refreshes of the same JWKS
	// Forced refreshes happen when a token references a key ID that isn't in the cached set, for example after the issuer rotates its keys
	defaultForcedRefreshInterval = 5 * time.Minute

	// Min and max intervals for the background refresh of a cached JWKS
	jwksMinRefreshInterval = 5 * time.Minute
	jwksMaxRefreshInterval = 24 * time.Hour

	// How long a resolved OIDC discovery document is cached after a success or a failure
	discoverySuccessTTL = time.Hour
	discoveryFailureTTL = 30 * time.Second

	// Timeout for a forced refresh of a JWKS
	// The refresh is shared by every request waiting for it, so it isn't tied to the context of the request that started it
	forcedRefreshTimeout = 30 * time.Second
	// Timeout for removing a JWKS from the cache
	unregisterTimeout = 5 * time.Second

	// A JWKS that isn't used for this long is removed from the cache, so it stops being refreshed in the background
	unusedJWKSTTL = 48 * time.Hour
	// How often unused JWKS are pruned
	pruneInterval = time.Hour
)

// NewVerifierOptions contains the options for NewVerifier
type NewVerifierOptions struct {
	// HTTP client used to fetch OIDC discovery documents and JWKS
	// If nil, uses NewHTTPClient with the default options
	HTTPClient *http.Client
	// Logger for errors in background JWKS refreshes
	Logger *slog.Logger
}

// Verifier verifies JWTs against trusted issuer configurations
// Signing keys are fetched from each issuer's JWKS and kept in a cache that is refreshed in the background
type Verifier struct {
	httpClient *http.Client
	log        *slog.Logger

	// Minimum time between forced refreshes of the same JWKS
	forcedRefreshInterval time.Duration
	// Used by tests to control the passing of time
	now func() time.Time

	lock      sync.Mutex
	cache     *jwkfetch.Cache
	closed    bool
	jwks      map[string]*jwksEntry
	discovery map[string]discoveryEntry
	lastPrune time.Time

	// Closed by Close, to signal in-flight operations that use the cache to stop
	closeCh chan struct{}
	// Operations that are using the cache
	// Close waits for them before shutting the cache down, because the cache can panic when it's shut down while in use
	inFlight sync.WaitGroup

	// Coalesces concurrent forced refreshes of the same JWKS, so requests that need one while it's in progress wait for it instead of failing
	refreshes singleflight.Group
}

type jwksEntry struct {
	lastUsed          time.Time
	lastForcedRefresh time.Time
}

type discoveryEntry struct {
	jwksURL string
	err     error
	expires time.Time
}

// NewVerifier returns a new Verifier
// The JWKS cache is started lazily on first use, and Close must be called to stop its background workers
func NewVerifier(opts NewVerifierOptions) *Verifier {
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = NewHTTPClient(HTTPClientOptions{})
	}

	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	return &Verifier{
		httpClient:            httpClient,
		log:                   log,
		forcedRefreshInterval: defaultForcedRefreshInterval,
		now:                   time.Now,
		jwks:                  map[string]*jwksEntry{},
		discovery:             map[string]discoveryEntry{},
		closeCh:               make(chan struct{}),
	}
}

// Close stops the background refresh of the JWKS cache
// In-flight calls to Verify are cancelled, and Close waits for them to return
// It is safe to call Close more than once
func (v *Verifier) Close(ctx context.Context) error {
	v.lock.Lock()
	if v.closed {
		v.lock.Unlock()
		return nil
	}
	v.closed = true
	cache := v.cache
	v.lock.Unlock()

	close(v.closeCh)
	if cache == nil {
		return nil
	}

	// No new operations can start once closed is set, so this waits only for the ones in progress
	done := make(chan struct{})
	go func() {
		v.inFlight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for in-flight operations to complete: %w", ctx.Err())
	}

	err := cache.Shutdown(ctx)
	if err != nil {
		return err
	}

	return nil
}

// Verify checks that the token is signed by the issuer's keys and that its claims match cfg
// It returns the verified claims
func (v *Verifier) Verify(ctx context.Context, token string, cfg IssuerConfig) (*Claims, error) {
	if len(token) > MaxTokenSize {
		return nil, fmt.Errorf("%w: token is larger than %d bytes", ErrInvalidToken, MaxTokenSize)
	}

	jwksURL, err := v.resolveJWKSURL(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyFetch, err)
	}

	set, err := v.keySet(ctx, jwksURL, peekKeyID(token))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyFetch, err)
	}

	tok, err := jwt.ParseString(token,
		// Many issuers (like Entra ID) publish keys without an `alg`, so the algorithm is inferred from the key type
		// Symmetric keys have already been removed from the set
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true), jws.WithUseDefault(true)),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(clockSkew),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.Audience),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithRequiredClaim(jwt.SubjectKey),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	claims := claimsFromToken(tok)
	if !MatchSubject(cfg.Subject, claims.Subject) {
		return nil, fmt.Errorf("%w: subject %q does not match the expected pattern", ErrInvalidToken, claims.Subject)
	}

	return claims, nil
}

// resolveJWKSURL returns the configured JWKS URL, or resolves it with OIDC discovery
func (v *Verifier) resolveJWKSURL(ctx context.Context, cfg IssuerConfig) (string, error) {
	if cfg.JWKSURL != "" {
		return cfg.JWKSURL, nil
	}

	now := v.now()

	v.lock.Lock()
	cached, ok := v.discovery[cfg.Issuer]
	v.lock.Unlock()
	if ok && now.Before(cached.expires) {
		return cached.jwksURL, cached.err
	}

	// Concurrent callers may fetch the same document at the same time, which is harmless
	jwksURL, err := v.fetchDiscovery(ctx, cfg.Issuer)

	entry := discoveryEntry{
		jwksURL: jwksURL,
		err:     err,
		expires: now.Add(discoverySuccessTTL),
	}
	if err != nil {
		entry.expires = now.Add(discoveryFailureTTL)
	}

	v.lock.Lock()
	v.discovery[cfg.Issuer] = entry
	v.lock.Unlock()

	return jwksURL, err
}

// fetchDiscovery retrieves the issuer's OIDC discovery document and returns its `jwks_uri`
func (v *Verifier) fetchDiscovery(ctx context.Context, issuer string) (string, error) {
	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	res, err := v.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch discovery document from %q: %w", u, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch discovery document from %q: unexpected status code %d", u, res.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, maxDiscoveryDocumentSize+1))
	if err != nil {
		return "", fmt.Errorf("failed to read discovery document from %q: %w", u, err)
	}
	if len(body) > maxDiscoveryDocumentSize {
		return "", fmt.Errorf("discovery document from %q is larger than %d bytes", u, maxDiscoveryDocumentSize)
	}

	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	err = json.Unmarshal(body, &doc)
	if err != nil {
		return "", fmt.Errorf("failed to parse discovery document from %q: %w", u, err)
	}

	// Per spec, the issuer in the document must be identical to the one used to build the URL
	if doc.Issuer != issuer {
		return "", fmt.Errorf("discovery document from %q is for issuer %q, not %q", u, doc.Issuer, issuer)
	}

	err = validateHTTPSURL(doc.JWKSURI)
	if err != nil {
		return "", fmt.Errorf("discovery document from %q has an invalid jwks_uri: %w", u, err)
	}

	return doc.JWKSURI, nil
}

// keySet returns the asymmetric keys in the JWKS at u
// If kid is not in the cached set, the JWKS is refreshed first, at most once per forcedRefreshInterval
func (v *Verifier) keySet(parentCtx context.Context, u string, kid string) (jwk.Set, error) {
	cache, release, err := v.acquireCache()
	if err != nil {
		return nil, err
	}
	defer release()

	ctx, cancel := v.contextUntilClosed(parentCtx)
	defer cancel()

	// Record the use, and stop refreshing JWKS that haven't been used in a while
	v.markUsed(ctx, cache, u)

	if !cache.IsRegistered(ctx, u) {
		// Don't wait for the first fetch in the background: it's forced below, so errors are returned right away
		err = cache.Register(ctx, u,
			jwkfetch.WithWaitReady(false),
			jwkfetch.WithMinInterval(jwksMinRefreshInterval),
			jwkfetch.WithMaxInterval(jwksMaxRefreshInterval),
		)
		if err != nil && !errors.Is(err, httprc.ErrResourceAlreadyExists()) {
			return nil, err
		}
	}

	set, err := cache.Lookup(ctx, u)

	// Force a refresh if the JWKS hasn't been fetched successfully yet, or if it doesn't have the key the token was signed with
	needsRefresh := err != nil
	if !needsRefresh && kid != "" {
		_, found := set.LookupKeyID(kid)
		needsRefresh = !found
	}
	if needsRefresh {
		set, err = v.forceRefresh(ctx, u)
	}
	if err != nil {
		return nil, err
	}

	return asymmetricKeys(set)
}

// forceRefresh fetches the JWKS at u again, and returns it
// Concurrent callers share a single fetch
// Fetches are rate-limited: when a new one isn't allowed yet, it returns the cached JWKS instead, which a fetch that completed in the meantime may have updated
func (v *Verifier) forceRefresh(ctx context.Context, u string) (jwk.Set, error) {
	ch := v.refreshes.DoChan(u, func() (any, error) {
		// The refresh can outlive the request that started it, since other requests may be waiting for it
		// So, it isn't cancelled with that request's context, and it holds its own reference to the cache
		cache, release, err := v.acquireCache()
		if err != nil {
			return nil, err
		}
		defer release()

		refreshCtx, cancel := v.contextUntilClosed(context.WithoutCancel(ctx))
		defer cancel()
		refreshCtx, cancelTimeout := context.WithTimeout(refreshCtx, forcedRefreshTimeout)
		defer cancelTimeout()

		if !v.allowForcedRefresh(u) {
			return cache.Lookup(refreshCtx, u)
		}

		return cache.Refresh(refreshCtx, u)
	})

	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}

		set, ok := res.Val.(jwk.Set)
		if !ok {
			return nil, errors.New("unexpected result from JWKS refresh")
		}

		return set, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// contextUntilClosed returns a copy of parentCtx that is also cancelled when the verifier is closed
// The caller must call cancel once the operation is done
func (v *Verifier) contextUntilClosed(parentCtx context.Context) (ctx context.Context, cancel context.CancelFunc) {
	ctx, cancel = context.WithCancel(parentCtx)

	// The goroutine returns when the context is done, including when the caller calls cancel
	go func() {
		select {
		case <-v.closeCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	return ctx, cancel
}

// acquireCache returns the JWKS cache, starting it on first use
// The caller must call release once it's done using the cache
func (v *Verifier) acquireCache() (cache *jwkfetch.Cache, release func(), err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.closed {
		return nil, nil, errors.New("verifier is closed")
	}

	if v.cache == nil {
		v.cache, err = v.newCache()
		if err != nil {
			return nil, nil, err
		}
	}

	v.inFlight.Add(1)
	return v.cache, v.inFlight.Done, nil
}

// newCache starts a new JWKS cache
func (v *Verifier) newCache() (*jwkfetch.Cache, error) {
	client := httprc.NewClient(
		httprc.WithErrorSink(errsink.NewFunc(func(ctx context.Context, err error) {
			v.log.WarnContext(ctx, "Failed to refresh a JWKS in the background", slog.Any("error", err))
		})),
	)

	// The cache's workers live until Close is called, so they must not be tied to the context of the request that started them
	cache, err := jwkfetch.NewCache(context.Background(), client, jwkfetch.WithHTTPClient(v.httpClient))
	if err != nil {
		return nil, fmt.Errorf("failed to start JWKS cache: %w", err)
	}

	return cache, nil
}

// markUsed records that the JWKS at u was used, and removes JWKS that haven't been used recently from the cache
func (v *Verifier) markUsed(ctx context.Context, cache *jwkfetch.Cache, u string) {
	now := v.now()

	v.lock.Lock()
	defer v.lock.Unlock()

	entry, ok := v.jwks[u]
	if !ok {
		entry = &jwksEntry{}
		v.jwks[u] = entry
	}
	entry.lastUsed = now

	if now.Sub(v.lastPrune) < pruneInterval {
		return
	}
	v.lastPrune = now

	for pu, pe := range v.jwks {
		if now.Sub(pe.lastUsed) < unusedJWKSTTL {
			continue
		}

		// Unregister while holding the lock: a concurrent request for the same URL marks it as used first, so it either keeps the JWKS from being pruned, or finds it unregistered and registers it again
		// Without the lock, the JWKS could be removed from the cache while that request is using it
		// Close waits for the lock before signaling operations to stop, so the unregistration only needs a timeout
		delete(v.jwks, pu)
		unregisterCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), unregisterTimeout)
		_ = cache.Unregister(unregisterCtx, pu)
		cancel()
	}

	for issuer, de := range v.discovery {
		if now.After(de.expires) {
			delete(v.discovery, issuer)
		}
	}
}

// allowForcedRefresh returns true if a forced refresh of the JWKS at u is allowed now, and records it
func (v *Verifier) allowForcedRefresh(u string) bool {
	now := v.now()

	v.lock.Lock()
	defer v.lock.Unlock()

	entry, ok := v.jwks[u]
	if !ok {
		entry = &jwksEntry{}
		v.jwks[u] = entry
	}

	if !entry.lastForcedRefresh.IsZero() && now.Sub(entry.lastForcedRefresh) < v.forcedRefreshInterval {
		return false
	}
	entry.lastForcedRefresh = now

	return true
}

// asymmetricKeys returns a new set that contains only the asymmetric keys in set
// An issuer's JWKS is public, so a symmetric key in it would let anyone forge tokens
func asymmetricKeys(set jwk.Set) (jwk.Set, error) {
	out := jwk.NewSet()
	for i := range set.Len() {
		key, ok := set.Key(i)
		if !ok || key.KeyType() == jwa.OctetSeq() {
			continue
		}

		err := out.AddKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to copy key: %w", err)
		}
	}

	if out.Len() == 0 {
		return nil, errors.New("the JWKS doesn't contain any asymmetric keys")
	}

	return out, nil
}
