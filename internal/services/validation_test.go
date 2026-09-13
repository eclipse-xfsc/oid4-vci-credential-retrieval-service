package services

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
)

func makeUnsignedShapeJWT(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p) + ".AA"
}

func TestValidateHolderBinding(t *testing.T) {
	now := time.Now().Unix()
	jwt := makeUnsignedShapeJWT(t,
		map[string]any{"typ": "openid4vci-proof+jwt", "alg": "ES256", "kid": "did:web:wallet.example#key-1"},
		map[string]any{"nonce": "n-1", "aud": "https://issuer.example", "iat": now},
	)
	if err := ValidateHolderBinding(jwt, "n-1", "https://issuer.example"); err != nil {
		t.Fatalf("expected structurally valid proof, got %v", err)
	}
}

func TestValidateHolderBindingRejectsWrongAudience(t *testing.T) {
	jwt := makeUnsignedShapeJWT(t,
		map[string]any{"typ": "openid4vci-proof+jwt", "alg": "ES256", "kid": "key-1"},
		map[string]any{"nonce": "n-1", "aud": "https://other.example", "iat": time.Now().Unix()},
	)
	if err := ValidateHolderBinding(jwt, "n-1", "https://issuer.example"); err == nil {
		t.Fatal("expected audience mismatch")
	}
}

func TestValidateRemoteURI(t *testing.T) {
	if err := validateRemoteURI("https://issuer.example/status/1", false); err != nil {
		t.Fatalf("https URI rejected: %v", err)
	}
	for _, raw := range []string{
		"http://issuer.example/status/1",
		"https://127.0.0.1/status/1",
		"https://user:pass@issuer.example/status/1",
		"https://issuer.example/status/1#fragment",
	} {
		if err := validateRemoteURI(raw, false); err == nil {
			t.Fatalf("expected URI to be rejected: %s", raw)
		}
	}
}

func TestDecodeCompressedBitstring(t *testing.T) {
	var b strings.Builder
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write([]byte{0x80, 0x00})
	_ = zw.Close()
	encoded := "u" + base64.RawURLEncoding.EncodeToString([]byte(b.String()))
	decoded, err := decodeCompressedBitstring(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0] != 0x80 {
		t.Fatalf("unexpected decoded list: %v", decoded)
	}
}

func TestValidateCredentialIssuerURIRejectsUnsafeIssuer(t *testing.T) {
	// Use JSON round-tripping because the library model may expose the field under
	// a version-specific Go name while the wire representation is stable.
	var offer credential.CredentialOfferParameters
	if err := json.Unmarshal([]byte(`{"credential_issuer":"http://127.0.0.1:8080","credential_configuration_ids":["test"]}`), &offer); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCredentialIssuerURI(&offer); err == nil {
		t.Fatal("expected unsafe credential issuer URI to be rejected")
	}
}

func TestResolveVerificationKeysRejectsEmbeddedJWKTrustAnchor(t *testing.T) {
	_, err := resolveVerificationKeys(context.Background(), "https://issuer.example", map[string]any{
		"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
	})
	if err == nil || !strings.Contains(err.Error(), "trust anchor") {
		t.Fatalf("expected embedded JWK trust-anchor rejection, got %v", err)
	}
}
