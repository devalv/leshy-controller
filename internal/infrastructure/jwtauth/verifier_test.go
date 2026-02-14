package jwtauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devalv/leshy-controller/internal/application/management"
	"github.com/golang-jwt/jwt/v5"
)

func TestVerifierValidateSettings(t *testing.T) {
	t.Parallel()

	_, privateKey, kid, jwksURL := createJWKSFixture(t)
	_ = privateKey

	v := NewVerifier(VerifierOptions{})
	err := v.ValidateSettings(context.Background(), management.Settings{JWKSURL: jwksURL})
	if err != nil {
		t.Fatalf("ValidateSettings() error = %v, want nil", err)
	}

	if kid == "" {
		t.Fatal("kid must not be empty")
	}
}

func TestVerifierVerifyAccessToken(t *testing.T) {
	t.Parallel()

	pub, privateKey, kid, jwksURL := createJWKSFixture(t)
	_ = pub

	now := time.Date(2026, time.February, 7, 12, 0, 0, 0, time.UTC)
	settings := management.Settings{
		Issuer:        "https://auth.example.com",
		Audience:      "leshy-controller",
		JWKSURL:       jwksURL,
		RequiredScope: "allow:write",
	}

	validToken := signToken(t, tokenInput{
		privateKey: privateKey, // pragma: allowlist secret
		kid:        kid,
		issuer:     settings.Issuer,
		audience:   settings.Audience,
		scope:      "allow:write stats:read",
		now:        now,
	})

	tokenWithoutScope := signToken(t, tokenInput{
		privateKey: privateKey, // pragma: allowlist secret
		kid:        kid,
		issuer:     settings.Issuer,
		audience:   settings.Audience,
		scope:      "stats:read",
		now:        now,
	})

	tokenUnknownKid := signToken(t, tokenInput{
		privateKey: privateKey, // pragma: allowlist secret
		kid:        "kid-unknown",
		issuer:     settings.Issuer,
		audience:   settings.Audience,
		scope:      "allow:write",
		now:        now,
	})

	tests := []struct {
		name    string
		token   string
		options VerifierOptions
		wantErr error
	}{
		{
			name:  "success",
			token: validToken,
			options: VerifierOptions{
				Now: func() time.Time {
					return now
				},
			},
		},
		{
			name:  "missing required scope",
			token: tokenWithoutScope,
			options: VerifierOptions{
				Now: func() time.Time {
					return now
				},
			},
			wantErr: management.ErrInvalidAccessToken,
		},
		{
			name:  "key id is not present in jwks",
			token: tokenUnknownKid,
			options: VerifierOptions{
				Now: func() time.Time {
					return now
				},
			},
			wantErr: management.ErrInvalidAccessToken,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewVerifier(tt.options)
			err := v.VerifyAccessToken(context.Background(), settings, tt.token)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifierVerifyAccessTokenJWKSUnavailable(t *testing.T) {
	t.Parallel()

	pub, privateKey, kid, _ := createJWKSFixture(t)
	_ = pub

	now := time.Date(2026, time.February, 7, 12, 0, 0, 0, time.UTC)
	token := signToken(t, tokenInput{
		privateKey: privateKey, // pragma: allowlist secret
		kid:        kid,
		issuer:     "https://auth.example.com",
		audience:   "leshy-controller",
		scope:      "allow:write",
		now:        now,
	})

	brokenJWKS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream is down", http.StatusInternalServerError)
	}))
	t.Cleanup(brokenJWKS.Close)

	v := NewVerifier(VerifierOptions{
		Now: func() time.Time { return now },
	})

	err := v.VerifyAccessToken(context.Background(), management.Settings{
		Issuer:        "https://auth.example.com",
		Audience:      "leshy-controller",
		JWKSURL:       brokenJWKS.URL,
		RequiredScope: "allow:write",
	}, token)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, management.ErrAuthorizationUnavailable) {
		t.Fatalf("error = %v, want %v", err, management.ErrAuthorizationUnavailable)
	}
}

func createJWKSFixture(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string, string) {
	t.Helper()

	pub, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() failed: %v", err)
	}

	const kid = "kid-1"
	body, err := json.Marshal(map[string]any{
		"keys": []map[string]string{
			{
				"kty": "OKP",
				"crv": "Ed25519",
				"kid": kid,
				"x":   base64.RawURLEncoding.EncodeToString(pub),
			},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)

	return pub, privateKey, kid, server.URL
}

type tokenInput struct {
	privateKey ed25519.PrivateKey
	kid        string
	issuer     string
	audience   string
	scope      string
	now        time.Time
}

func signToken(t *testing.T, in tokenInput) string {
	t.Helper()

	claims := allowClaims{
		Scope: in.scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    in.issuer,
			Audience:  jwt.ClaimStrings{in.audience},
			ExpiresAt: jwt.NewNumericDate(in.now.Add(5 * time.Minute)),
			NotBefore: jwt.NewNumericDate(in.now.Add(-1 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(in.now.Add(-1 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = in.kid

	signed, err := token.SignedString(in.privateKey)
	if err != nil {
		t.Fatalf("token.SignedString() failed: %v", err)
	}

	return signed
}
