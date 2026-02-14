package jwtauth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/devalv/leshy-controller/internal/application/management"
	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultHTTPTimeout = 5 * time.Second
	defaultCacheTTL    = 5 * time.Minute
	defaultLeeway      = 30 * time.Second
	maxJWKSBodyBytes   = 1 << 20
)

type VerifierOptions struct {
	HTTPClient *http.Client
	CacheTTL   time.Duration
	Leeway     time.Duration
	Now        func() time.Time
}

type Verifier struct {
	httpClient *http.Client
	cacheTTL   time.Duration
	leeway     time.Duration
	now        func() time.Time

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	keys      map[string]ed25519.PublicKey
	expiresAt time.Time
}

type allowClaims struct {
	jwt.RegisteredClaims

	Scope string   `json:"scope"`
	SCP   []string `json:"scp"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

func NewVerifier(opts VerifierOptions) *Verifier {
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}

	cacheTTL := opts.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = defaultCacheTTL
	}

	leeway := opts.Leeway
	if leeway < 0 {
		leeway = 0
	}
	if leeway == 0 {
		leeway = defaultLeeway
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	return &Verifier{
		httpClient: httpClient,
		cacheTTL:   cacheTTL,
		leeway:     leeway,
		now:        now,
		cache:      make(map[string]cacheEntry),
	}
}

func (v *Verifier) ValidateSettings(ctx context.Context, settings management.Settings) error {
	_, err := v.keysForJWKS(ctx, settings.JWKSURL, false)
	if err != nil {
		return fmt.Errorf("load jwks: %w", err)
	}

	return nil
}

func (v *Verifier) VerifyAccessToken(
	ctx context.Context,
	settings management.Settings,
	accessToken string,
) error {
	claims := allowClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(settings.Issuer),
		jwt.WithAudience(settings.Audience),
		jwt.WithLeeway(v.leeway),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithTimeFunc(v.now),
	)

	keyFunc := func(token *jwt.Token) (any, error) {
		if token == nil || token.Method == nil || token.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
			return nil, fmt.Errorf("%w: unexpected signing method", management.ErrInvalidAccessToken)
		}

		kid, ok := token.Header["kid"].(string)
		if !ok || strings.TrimSpace(kid) == "" {
			return nil, fmt.Errorf("%w: kid header is required", management.ErrInvalidAccessToken)
		}

		keys, err := v.keysForJWKS(ctx, settings.JWKSURL, false)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", management.ErrAuthorizationUnavailable, err.Error())
		}

		key, found := keys[kid]
		if found {
			return key, nil
		}

		keys, err = v.keysForJWKS(ctx, settings.JWKSURL, true)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", management.ErrAuthorizationUnavailable, err.Error())
		}

		key, found = keys[kid]
		if !found {
			return nil, fmt.Errorf("%w: key id %q not found in jwks", management.ErrInvalidAccessToken, kid)
		}

		return key, nil
	}

	parsed, err := parser.ParseWithClaims(accessToken, &claims, keyFunc)
	if err != nil {
		if errors.Is(err, management.ErrAuthorizationUnavailable) {
			return management.ErrAuthorizationUnavailable
		}

		return fmt.Errorf("%w: %s", management.ErrInvalidAccessToken, err.Error())
	}
	if parsed == nil || !parsed.Valid {
		return fmt.Errorf("%w: token is not valid", management.ErrInvalidAccessToken)
	}

	if !hasRequiredScope(claims.Scope, claims.SCP, settings.RequiredScope) {
		return fmt.Errorf("%w: missing required scope %q", management.ErrInvalidAccessToken, settings.RequiredScope)
	}

	return nil
}

func hasRequiredScope(scopeValue string, scpValues []string, requiredScope string) bool {
	if requiredScope == "" {
		return true
	}

	for _, candidate := range strings.Fields(scopeValue) {
		if candidate == requiredScope {
			return true
		}
	}

	for _, candidate := range scpValues {
		if strings.TrimSpace(candidate) == requiredScope {
			return true
		}
	}

	return false
}

func (v *Verifier) keysForJWKS(
	ctx context.Context,
	jwksURL string,
	forceRefresh bool,
) (map[string]ed25519.PublicKey, error) {
	if !forceRefresh {
		if keys, ok := v.cachedKeys(jwksURL); ok {
			return keys, nil
		}
	}

	keys, err := v.fetchKeys(ctx, jwksURL)
	if err != nil {
		return nil, err
	}

	v.mu.Lock()
	v.cache[jwksURL] = cacheEntry{
		keys:      keys,
		expiresAt: v.now().Add(v.cacheTTL),
	}
	v.mu.Unlock()

	return cloneKeys(keys), nil
}

func (v *Verifier) cachedKeys(jwksURL string) (map[string]ed25519.PublicKey, bool) {
	v.mu.RLock()
	entry, ok := v.cache[jwksURL]
	v.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if v.now().After(entry.expiresAt) {
		return nil, false
	}

	return cloneKeys(entry.keys), true
}

func (v *Verifier) fetchKeys(ctx context.Context, jwksURL string) (map[string]ed25519.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create jwks request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute jwks request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected jwks status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read jwks response body: %w", err)
	}

	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode jwks response body: %w", err)
	}

	keys := make(map[string]ed25519.PublicKey)
	for _, key := range doc.Keys {
		if key.Kty != "OKP" || key.Crv != "Ed25519" {
			continue
		}

		kid := strings.TrimSpace(key.Kid)
		if kid == "" {
			continue
		}

		raw, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			return nil, fmt.Errorf("decode jwks key %q: %w", kid, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("unexpected public key size for key %q", kid)
		}

		keys[kid] = ed25519.PublicKey(raw)
	}

	if len(keys) == 0 {
		return nil, errors.New("no ed25519 keys found in jwks")
	}

	return keys, nil
}

func cloneKeys(source map[string]ed25519.PublicKey) map[string]ed25519.PublicKey {
	keys := make(map[string]ed25519.PublicKey, len(source))
	for kid, key := range source {
		copied := make([]byte, len(key))
		copy(copied, key)
		keys[kid] = ed25519.PublicKey(copied)
	}

	return keys
}
