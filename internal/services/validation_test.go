package services

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/config"
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

func credentialResponseForValidation(t *testing.T, raw string) credential.CredentialResponse {
	t.Helper()
	var response credential.CredentialResponse
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		t.Fatalf("decode credential response: %v", err)
	}
	return response
}

func TestValidateCredentialResponseAcceptsSDJWT(t *testing.T) {
	original := verifyIssuedCredentialProof
	verifyIssuedCredentialProof = func(_ context.Context, raw []byte, format string) error {
		if format != "dc+sd-jwt" {
			t.Fatalf("expected dc+sd-jwt format, got %q", format)
		}
		if !strings.Contains(string(raw), "~") {
			t.Fatalf("expected complete SD-JWT including disclosures, got %q", string(raw))
		}
		return nil
	}
	t.Cleanup(func() { verifyIssuedCredentialProof = original })

	issuer := "https://issuer.example"
	jwt := makeUnsignedShapeJWT(t,
		map[string]any{"typ": "dc+sd-jwt", "alg": "ES256", "kid": "did:web:issuer.example#key-1"},
		map[string]any{
			"iss": issuer,
			"iat": time.Now().Add(-time.Minute).Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"vct": "https://credentials.example/employee",
			"_sd": []any{"disclosure-digest"},
		},
	)
	response := credentialResponseForValidation(t, `{"credentials":[{"credential":`+strconv.Quote(jwt+"~WyJzYWx0IiwibmFtZSIsIkFsaWNlIl0~")+`}]}`)

	if err := ValidateCredentialResponse(context.Background(), &response, issuer); err != nil {
		t.Fatalf("expected SD-JWT VC to be accepted, got %v", err)
	}
}

func TestValidateCredentialResponseAcceptsLDPVC(t *testing.T) {
	original := verifyIssuedCredentialProof
	verifyIssuedCredentialProof = func(_ context.Context, raw []byte, format string) error {
		if format != "ldp_vc" {
			t.Fatalf("expected ldp_vc format, got %q", format)
		}
		var vc map[string]any
		if err := json.Unmarshal(raw, &vc); err != nil {
			t.Fatalf("expected LDP VC JSON body, got %v", err)
		}
		return nil
	}
	t.Cleanup(func() { verifyIssuedCredentialProof = original })
	issuer := "https://issuer.example"
	response := credentialResponseForValidation(t, `{
		"credentials":[{
			"credential":{
				"@context":["https://www.w3.org/2018/credentials/v1"],
				"id":"urn:uuid:1234",
				"type":["VerifiableCredential","EmployeeCredential"],
				"issuer":"https://issuer.example",
				"validFrom":"2026-01-01T00:00:00Z",
				"validUntil":"2030-01-01T00:00:00Z",
				"credentialSubject":{"id":"did:example:holder","name":"Alice"},
				"proof":{
					"type":"DataIntegrityProof",
					"cryptosuite":"eddsa-rdfc-2022",
					"verificationMethod":"https://issuer.example/keys/1",
					"proofPurpose":"assertionMethod",
					"proofValue":"zExampleProofValue"
				}
			}
		}]
	}`)

	if err := ValidateCredentialResponse(context.Background(), &response, issuer); err != nil {
		t.Fatalf("expected LDP VC to be accepted, got %v", err)
	}
}

func TestValidateCredentialResponseRejectsLDPVCWithoutProof(t *testing.T) {
	response := credentialResponseForValidation(t, `{
		"credentials":[{"credential":{
			"@context":["https://www.w3.org/2018/credentials/v1"],
			"type":["VerifiableCredential"],
			"issuer":"https://issuer.example",
			"credentialSubject":{"id":"did:example:holder"}
		}}]
	}`)

	err := ValidateCredentialResponse(context.Background(), &response, "https://issuer.example")
	if err == nil || !strings.Contains(err.Error(), "has no proof") {
		t.Fatalf("expected missing LDP proof to be rejected, got %v", err)
	}
}

func TestValidateCredentialResponseRejectsIssuerMismatchForLDPVC(t *testing.T) {
	response := credentialResponseForValidation(t, `{
		"credentials":[{"credential":{
			"type":["VerifiableCredential"],
			"issuer":"https://other.example",
			"credentialSubject":{"id":"did:example:holder"},
			"proof":{"type":"DataIntegrityProof","verificationMethod":"https://other.example/keys/1","proofValue":"zProof"}
		}}]
	}`)

	err := ValidateCredentialResponse(context.Background(), &response, "https://issuer.example")
	if err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("expected issuer mismatch to be rejected, got %v", err)
	}
}

func TestVerifyCredentialWithSignerFormats(t *testing.T) {
	tests := []struct {
		name   string
		format string
		body   string
	}{
		{name: "sd-jwt", format: "dc+sd-jwt", body: "header.payload.signature~disclosure~"},
		{name: "ldp-vc", format: "ldp_vc", body: `{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiableCredential"],"proof":{"type":"JsonWebSignature2020"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/credential/verify" {
					t.Fatalf("unexpected signer path %q", r.URL.Path)
				}
				if r.Method != http.MethodPost {
					t.Fatalf("unexpected signer method %q", r.Method)
				}
				if got := r.Header.Get("x-format"); got != tt.format {
					t.Fatalf("expected x-format %q, got %q", tt.format, got)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if string(body) != tt.body {
					t.Fatalf("expected credential body %q, got %q", tt.body, string(body))
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"valid":true}`))
			}))
			defer server.Close()

			previous := config.CurrentCredentialRetrievalConfig.SignerURL
			config.CurrentCredentialRetrievalConfig.SignerURL = server.URL
			t.Cleanup(func() { config.CurrentCredentialRetrievalConfig.SignerURL = previous })

			if err := verifyCredentialWithSigner(context.Background(), []byte(tt.body), tt.format); err != nil {
				t.Fatalf("expected signer verification to succeed: %v", err)
			}
		})
	}
}

func TestVerifyCredentialWithSignerRejectsInvalidProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"valid":false}`))
	}))
	defer server.Close()
	previous := config.CurrentCredentialRetrievalConfig.SignerURL
	config.CurrentCredentialRetrievalConfig.SignerURL = server.URL
	t.Cleanup(func() { config.CurrentCredentialRetrievalConfig.SignerURL = previous })

	err := verifyCredentialWithSigner(context.Background(), []byte("credential"), "dc+sd-jwt")
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected invalid signer result to fail, got %v", err)
	}
}

func TestValidateCredentialResponseRejectsMalformedCredential(t *testing.T) {
	response := credentialResponseForValidation(t, `{"credentials":[{"credential":123}]}`)
	err := ValidateCredentialResponse(context.Background(), &response, "https://issuer.example")
	if err == nil || !strings.Contains(err.Error(), "compact JWT/SD-JWT string or an LDP VC JSON object") {
		t.Fatalf("expected unsupported credential representation to fail, got %v", err)
	}
}

func TestValidateCredentialResponseRejectsEmptySDJWT(t *testing.T) {
	response := credentialResponseForValidation(t, `{"credentials":[{"credential":"   "}]}`)
	err := ValidateCredentialResponse(context.Background(), &response, "https://issuer.example")
	if err == nil || !strings.Contains(err.Error(), "issued credential is empty") {
		t.Fatalf("expected empty credential to fail, got %v", err)
	}
}

func TestValidateCredentialResponseRejectsSDJWTWithoutIssuer(t *testing.T) {
	jwt := makeUnsignedShapeJWT(t,
		map[string]any{"typ": "dc+sd-jwt", "alg": "ES256"},
		map[string]any{"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()},
	)
	response := credentialResponseForValidation(t, `{"credentials":[{"credential":`+strconv.Quote(jwt+"~")+`}]}`)
	err := ValidateCredentialResponse(context.Background(), &response, "https://issuer.example")
	if err == nil || !strings.Contains(err.Error(), "has no issuer") {
		t.Fatalf("expected missing SD-JWT issuer to fail, got %v", err)
	}
}

func TestValidateCredentialResponseRejectsSDJWTIssuerMismatchBeforeSigner(t *testing.T) {
	called := false
	original := verifyIssuedCredentialProof
	verifyIssuedCredentialProof = func(_ context.Context, _ []byte, _ string) error {
		called = true
		return nil
	}
	t.Cleanup(func() { verifyIssuedCredentialProof = original })

	jwt := makeUnsignedShapeJWT(t,
		map[string]any{"typ": "dc+sd-jwt", "alg": "ES256"},
		map[string]any{"iss": "https://other.example", "exp": time.Now().Add(time.Hour).Unix()},
	)
	response := credentialResponseForValidation(t, `{"credentials":[{"credential":`+strconv.Quote(jwt+"~")+`}]}`)
	err := ValidateCredentialResponse(context.Background(), &response, "https://issuer.example")
	if err == nil || !strings.Contains(err.Error(), "not bound") {
		t.Fatalf("expected issuer mismatch to fail, got %v", err)
	}
	if called {
		t.Fatal("signer must not be called for an issuer-mismatched credential")
	}
}

func TestValidateCredentialResponsePropagatesSignerRejectionForSDJWT(t *testing.T) {
	original := verifyIssuedCredentialProof
	verifyIssuedCredentialProof = func(_ context.Context, _ []byte, format string) error {
		if format != "dc+sd-jwt" {
			t.Fatalf("unexpected format %q", format)
		}
		return errors.New("proof invalid")
	}
	t.Cleanup(func() { verifyIssuedCredentialProof = original })
	jwt := makeUnsignedShapeJWT(t,
		map[string]any{"typ": "dc+sd-jwt", "alg": "ES256"},
		map[string]any{"iss": "https://issuer.example", "exp": time.Now().Add(time.Hour).Unix()},
	)
	response := credentialResponseForValidation(t, `{"credentials":[{"credential":`+strconv.Quote(jwt+"~")+`}]}`)
	err := ValidateCredentialResponse(context.Background(), &response, "https://issuer.example")
	if err == nil || !strings.Contains(err.Error(), "proof invalid") {
		t.Fatalf("expected signer rejection to propagate, got %v", err)
	}
}

func TestValidateCredentialResponsePropagatesSignerRejectionForLDPVC(t *testing.T) {
	original := verifyIssuedCredentialProof
	verifyIssuedCredentialProof = func(_ context.Context, _ []byte, format string) error {
		if format != "ldp_vc" {
			t.Fatalf("unexpected format %q", format)
		}
		return errors.New("proof invalid")
	}
	t.Cleanup(func() { verifyIssuedCredentialProof = original })
	response := credentialResponseForValidation(t, `{"credentials":[{"credential":{"type":["VerifiableCredential"],"issuer":"https://issuer.example","credentialSubject":{"id":"did:example:holder"},"proof":{"type":"DataIntegrityProof","verificationMethod":"did:example:issuer#key-1","proofValue":"zProof"}}}]}`)
	err := ValidateCredentialResponse(context.Background(), &response, "https://issuer.example")
	if err == nil || !strings.Contains(err.Error(), "proof invalid") {
		t.Fatalf("expected signer rejection to propagate, got %v", err)
	}
}

func TestValidateCredentialResponseRejectsLDPVCWithoutVerifiableCredentialType(t *testing.T) {
	response := credentialResponseForValidation(t, `{"credentials":[{"credential":{"type":["EmployeeCredential"],"issuer":"https://issuer.example","credentialSubject":{"id":"did:example:holder"},"proof":{"type":"DataIntegrityProof","verificationMethod":"did:example:issuer#key-1","proofValue":"zProof"}}}]}`)
	err := ValidateCredentialResponse(context.Background(), &response, "https://issuer.example")
	if err == nil || !strings.Contains(err.Error(), "does not contain VerifiableCredential") {
		t.Fatalf("expected missing VC type to fail, got %v", err)
	}
}

func TestValidateCredentialResponseRejectsLDPVCWithoutCredentialSubject(t *testing.T) {
	response := credentialResponseForValidation(t, `{"credentials":[{"credential":{"type":["VerifiableCredential"],"issuer":"https://issuer.example","proof":{"type":"DataIntegrityProof","verificationMethod":"did:example:issuer#key-1","proofValue":"zProof"}}}]}`)
	err := ValidateCredentialResponse(context.Background(), &response, "https://issuer.example")
	if err == nil || !strings.Contains(err.Error(), "has no credentialSubject") {
		t.Fatalf("expected missing credentialSubject to fail, got %v", err)
	}
}

func TestVerifyCredentialWithSignerRejectsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "verification unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	previous := config.CurrentCredentialRetrievalConfig.SignerURL
	config.CurrentCredentialRetrievalConfig.SignerURL = server.URL
	t.Cleanup(func() { config.CurrentCredentialRetrievalConfig.SignerURL = previous })
	err := verifyCredentialWithSigner(context.Background(), []byte("credential"), "dc+sd-jwt")
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("expected signer HTTP error to fail closed, got %v", err)
	}
}

func TestVerifyCredentialWithSignerRejectsMalformedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer server.Close()
	previous := config.CurrentCredentialRetrievalConfig.SignerURL
	config.CurrentCredentialRetrievalConfig.SignerURL = server.URL
	t.Cleanup(func() { config.CurrentCredentialRetrievalConfig.SignerURL = previous })
	err := verifyCredentialWithSigner(context.Background(), []byte("credential"), "ldp_vc")
	if err == nil || !strings.Contains(err.Error(), "decode signer verification response") {
		t.Fatalf("expected malformed signer response to fail closed, got %v", err)
	}
}

func TestVerifyCredentialWithSignerRequiresConfiguration(t *testing.T) {
	previous := config.CurrentCredentialRetrievalConfig.SignerURL
	config.CurrentCredentialRetrievalConfig.SignerURL = ""
	t.Cleanup(func() { config.CurrentCredentialRetrievalConfig.SignerURL = previous })
	if err := verifyCredentialWithSigner(context.Background(), []byte("credential"), "ldp_vc"); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected missing signer configuration to fail, got %v", err)
	}
}
