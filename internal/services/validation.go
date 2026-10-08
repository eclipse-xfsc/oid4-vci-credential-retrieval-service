package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
)

const maxRemoteDocumentSize = 2 << 20 // 2 MiB

// ValidateCredentialIssuerURI validates the issuer URL before any network access is performed.
// This is deliberately separate from ValidateOffering so callers can prevent SSRF during
// issuer metadata discovery itself.
func ValidateCredentialIssuerURI(offer *credential.CredentialOfferParameters) error {
	if offer == nil {
		return errors.New("credential offer is nil")
	}
	offerMap, err := asMap(offer)
	if err != nil {
		return fmt.Errorf("marshal credential offer: %w", err)
	}
	issuer, _ := stringValue(offerMap, "credential_issuer", "credentialIssuer")
	if issuer == "" {
		return errors.New("credential offer misses credential_issuer")
	}
	if err := validateRemoteURI(issuer, config.CurrentCredentialRetrievalConfig.DisableTLS); err != nil {
		return fmt.Errorf("invalid credential_issuer: %w", err)
	}
	return nil
}

// ValidateOffering performs wallet-side checks which must happen before an offer is trusted.
func ValidateOffering(offer *credential.CredentialOfferParameters, metadata *credential.IssuerMetadata) error {
	if offer == nil || metadata == nil {
		return errors.New("offering or issuer metadata is nil")
	}

	offerMap, err := asMap(offer)
	if err != nil {
		return fmt.Errorf("marshal credential offer: %w", err)
	}
	issuer, _ := stringValue(offerMap, "credential_issuer", "credentialIssuer")
	if err := ValidateCredentialIssuerURI(offer); err != nil {
		return err
	}

	metadataMap, err := asMap(metadata)
	if err != nil {
		return fmt.Errorf("marshal issuer metadata: %w", err)
	}
	metadataIssuer, _ := stringValue(metadataMap, "credential_issuer", "credentialIssuer", "issuer")
	// Validate all issuer-advertised network endpoints before they can be used.
	for name, endpoint := range map[string]string{
		"credential_endpoint": metadata.CredentialEndpoint,
	} {
		if endpoint == "" {
			return fmt.Errorf("issuer metadata misses %s", name)
		}
		if err := validateRemoteURI(endpoint, config.CurrentCredentialRetrievalConfig.DisableTLS); err != nil {
			return fmt.Errorf("invalid %s: %w", name, err)
		}
	}
	if metadata.NonceEndpoint != nil && *metadata.NonceEndpoint != "" {
		if err := validateRemoteURI(*metadata.NonceEndpoint, config.CurrentCredentialRetrievalConfig.DisableTLS); err != nil {
			return fmt.Errorf("invalid nonce_endpoint: %w", err)
		}
	}
	for _, authorizationServer := range metadata.AuthorizationServers {
		if err := validateRemoteURI(authorizationServer, config.CurrentCredentialRetrievalConfig.DisableTLS); err != nil {
			return fmt.Errorf("invalid authorization_server: %w", err)
		}
	}
	if metadataIssuer != "" && metadataIssuer != issuer {
		return fmt.Errorf("issuer metadata credential_issuer mismatch: offer=%q metadata=%q", issuer, metadataIssuer)
	}

	ids := stringSliceValue(offerMap, "credential_configuration_ids", "credentials")
	if len(ids) == 0 {
		return errors.New("credential offer contains no credential_configuration_ids")
	}

	supported := nestedMap(metadataMap, "credential_configurations_supported", "credentialConfigurationsSupported")
	for _, id := range ids {
		if supported != nil {
			if _, ok := supported[id]; !ok {
				return fmt.Errorf("offered credential configuration %q is not present in issuer metadata", id)
			}
		}
	}
	return nil
}

// ValidateHolderBinding checks the proof returned by the signer before sending it to the issuer.
// Cryptographic verification of the holder proof itself is done by the issuer; here the Wallet
// ensures that the signer produced a structurally correct proof bound to the requested nonce/audience.
func ValidateHolderBinding(compact, nonce, audience string) error {
	header, claims, err := decodeJWT(compact)
	if err != nil {
		return fmt.Errorf("invalid holder proof JWT: %w", err)
	}
	if header["typ"] != "openid4vci-proof+jwt" {
		return fmt.Errorf("invalid holder proof typ %q", header["typ"])
	}
	alg, _ := header["alg"].(string)
	if alg == "" || alg == "none" || strings.HasPrefix(alg, "HS") {
		return fmt.Errorf("unsafe holder proof algorithm %q", alg)
	}
	keyHeaders := 0
	for _, k := range []string{"jwk", "kid", "x5c"} {
		if v, ok := header[k]; ok && v != nil && v != "" {
			keyHeaders++
		}
	}
	if keyHeaders != 1 {
		return errors.New("holder proof must contain exactly one of jwk, kid or x5c")
	}
	if got, _ := claims["nonce"].(string); nonce != "" && got != nonce {
		return fmt.Errorf("holder proof nonce mismatch")
	}
	if !audienceMatches(claims["aud"], audience) {
		return fmt.Errorf("holder proof audience mismatch")
	}
	iat, ok := numericDate(claims["iat"])
	if !ok {
		return errors.New("holder proof misses iat")
	}
	if delta := time.Since(iat); delta > 5*time.Minute || delta < -1*time.Minute {
		return fmt.Errorf("holder proof iat outside accepted clock window")
	}
	return nil
}

// CredentialVerificationContext carries tenant-scoped verification parameters.
type CredentialVerificationContext struct {
	Namespace       string
	Group           string
	TenantID        string
	GroupID         string
	DisclosureFrame []string
}

type credentialVerificationRequest struct {
	Credential      string   `json:"credential"`
	DisclosureFrame []string `json:"disclosureFrame,omitempty"`
}

// verifyIssuedCredentialProof is a test seam around the Crypto Provider Signer verification API.
// Production delegates cryptographic VC proof verification for both LDP VC and SD-JWT VC to
// POST /v1/credential/verify so this service does not maintain a second cryptographic stack.
var verifyIssuedCredentialProof = verifyCredentialWithSigner

// ValidateCredentialResponse validates every immediately issued credential before it is persisted.
// Compact JWT/SD-JWT and JSON-LD/LDP credentials delegate cryptographic proof verification to
// the Crypto Provider Signer. This service additionally enforces issuer binding and validity.
// Deferred responses are returned to the caller without storage.
func ValidateCredentialResponse(ctx context.Context, response *credential.CredentialResponse, expectedCredentialIssuer string, verificationContext ...CredentialVerificationContext) error {
	verifyContext := CredentialVerificationContext{}
	if len(verificationContext) > 0 {
		verifyContext = verificationContext[0]
	}
	if response == nil {
		return errors.New("credential response is nil")
	}
	if len(response.Credentials) == 0 {
		if response.TransactionID != "" {
			return errors.New("deferred credential issuance is not supported by retrieval service")
		}
		return errors.New("credential response contains no credentials")
	}
	for i, item := range response.Credentials {
		if err := validateIssuedCredential(ctx, item.Credential, expectedCredentialIssuer, verifyContext); err != nil {
			return fmt.Errorf("credential[%d]: %w", i, err)
		}
	}
	return nil
}

func validateIssuedCredential(ctx context.Context, raw json.RawMessage, expectedCredentialIssuer string, verifyContext CredentialVerificationContext) error {
	var compact string
	if err := json.Unmarshal(raw, &compact); err == nil {
		if strings.TrimSpace(compact) == "" {
			return errors.New("issued credential is empty")
		}
		slog.Info("Issued Credential", compact)
		return validateJWTIssuedCredential(ctx, compact, expectedCredentialIssuer, verifyContext)
	}
	var vc map[string]any
	if err := json.Unmarshal(raw, &vc); err != nil || vc == nil {
		return errors.New("issued credential must be a compact JWT/SD-JWT string or an LDP VC JSON object")
	}
	slog.Info("Issued Credential", vc)
	return validateLDPIssuedCredential(ctx, vc, expectedCredentialIssuer, verifyContext)
}

func validateJWTIssuedCredential(ctx context.Context, compact, expectedCredentialIssuer string, verifyContext CredentialVerificationContext) error {
	issuerJWT := strings.Split(compact, "~")[0]
	claims, err := decodeJWTClaims(issuerJWT)
	if err != nil {
		return fmt.Errorf("parse issued JWT/SD-JWT credential: %w", err)
	}
	issuer := issuerFromClaims(claims)
	if issuer == "" {
		return errors.New("issued JWT/SD-JWT credential has no issuer")
	}

	if expectedCredentialIssuer != "" && !credentialIssuerBound(claims, issuer, expectedCredentialIssuer) {
		return fmt.Errorf("issued credential issuer %q is not bound to credential issuer %q", issuer, expectedCredentialIssuer)
	}

	if err := verifyIssuedCredentialProof(ctx, []byte(compact), "dc+sd-jwt", verifyContext); err != nil {
		return fmt.Errorf("verify issued JWT/SD-JWT credential proof: %w", err)
	}

	if err := validateCredentialTimes(claims, time.Now().UTC()); err != nil {
		return err
	}
	return nil
}

func validateLDPIssuedCredential(ctx context.Context, vc map[string]any, expectedCredentialIssuer string, verifyContext CredentialVerificationContext) error {
	issuer := issuerFromClaims(vc)
	if issuer == "" {
		return errors.New("issued LDP VC has no issuer")
	}
	if !containsCredentialType(vc["type"]) {
		return errors.New("issued LDP VC type does not contain VerifiableCredential")
	}
	if mapValue(vc["credentialSubject"]) == nil {
		if subjects, ok := vc["credentialSubject"].([]any); !ok || len(subjects) == 0 {
			return errors.New("issued LDP VC has no credentialSubject")
		}
	}
	if err := validateLDPProofShape(vc["proof"]); err != nil {
		return err
	}
	if expectedCredentialIssuer != "" && !credentialIssuerBound(vc, issuer, expectedCredentialIssuer) {
		return fmt.Errorf("issued credential issuer %q is not bound to credential issuer %q", issuer, expectedCredentialIssuer)
	}
	rawVC, err := json.Marshal(vc)
	if err != nil {
		return fmt.Errorf("marshal issued LDP VC for proof verification: %w", err)
	}
	if err := verifyIssuedCredentialProof(ctx, rawVC, "ldp_vc", verifyContext); err != nil {
		return fmt.Errorf("verify issued LDP VC proof: %w", err)
	}
	if err := validateCredentialTimes(vc, time.Now().UTC()); err != nil {
		return err
	}
	return nil
}

func verifyCredentialWithSigner(ctx context.Context, rawCredential []byte, format string, verifyContext CredentialVerificationContext) error {
	baseURL := strings.TrimSpace(config.CurrentCredentialRetrievalConfig.SignerURL)
	if baseURL == "" {
		return errors.New("signer URL is not configured")
	}
	if format != "dc+sd-jwt" && format != "ldp_vc" {
		return fmt.Errorf("unsupported credential verification format %q", format)
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/v1/credential/verify"
	payload := map[string]any{"credential": base64.StdEncoding.EncodeToString(rawCredential)}
	if format == "dc+sd-jwt" {
		// Keep the field present even if no frame was supplied by the caller.
		payload["disclosureFrame"] = verifyContext.DisclosureFrame
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal signer verification request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create signer verification request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-format", format)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call signer verification endpoint: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		return fmt.Errorf("read signer verification response: %w", err)
	}
	if len(responseBody) > 1<<20 {
		return errors.New("signer verification response exceeds size limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("signer verification returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return fmt.Errorf("decode signer verification response: %w", err)
	}
	if !result.Valid {
		return errors.New("signer reported credential proof as invalid")
	}
	return nil
}

func containsCredentialType(raw any) bool {
	switch v := raw.(type) {
	case string:
		return v == "VerifiableCredential"
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == "VerifiableCredential" {
				return true
			}
		}
	}
	return false
}

func validateLDPProofShape(raw any) error {
	proofs := make([]map[string]any, 0, 1)
	if proof := mapValue(raw); proof != nil {
		proofs = append(proofs, proof)
	} else if list, ok := raw.([]any); ok {
		for _, item := range list {
			if proof := mapValue(item); proof != nil {
				proofs = append(proofs, proof)
			}
		}
	}
	if len(proofs) == 0 {
		return errors.New("issued LDP VC has no proof")
	}
	for _, proof := range proofs {
		if strings.TrimSpace(stringOrEmpty(proof["type"])) == "" {
			return errors.New("issued LDP VC proof has no type")
		}
		if strings.TrimSpace(stringOrEmpty(proof["verificationMethod"])) == "" {
			return errors.New("issued LDP VC proof has no verificationMethod")
		}
		if strings.TrimSpace(stringOrEmpty(proof["proofValue"])) == "" && strings.TrimSpace(stringOrEmpty(proof["jws"])) == "" {
			return errors.New("issued LDP VC proof has neither proofValue nor jws")
		}
	}
	return nil
}

// fetchCredentialNonce implements the OID4VCI 1.0 nonce endpoint flow.
// The endpoint is issuer-controlled metadata but still treated as untrusted network input.
func fetchCredentialNonce(ctx context.Context, metadata *credential.IssuerMetadata, credentialIssuer string) (string, error) {
	if metadata == nil || metadata.NonceEndpoint == nil || strings.TrimSpace(*metadata.NonceEndpoint) == "" {
		return "", nil
	}
	rawURL := strings.TrimSpace(*metadata.NonceEndpoint)
	if err := validateRemoteURI(rawURL, config.CurrentCredentialRetrievalConfig.DisableTLS); err != nil {
		return "", fmt.Errorf("invalid nonce endpoint: %w", err)
	}
	if !sameOrigin(rawURL, credentialIssuer) {
		return "", errors.New("nonce endpoint origin is not bound to credential issuer")
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: safeDialContext},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if err := validateRemoteURI(req.URL.String(), config.CurrentCredentialRetrievalConfig.DisableTLS); err != nil {
				return err
			}
			if !sameOrigin(req.URL.String(), credentialIssuer) {
				return errors.New("nonce redirect leaves credential issuer origin")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("nonce endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return "", err
	}
	if len(body) > 64*1024 {
		return "", errors.New("nonce response exceeds size limit")
	}
	var payload struct {
		CNonce string `json:"c_nonce"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decode nonce response: %w", err)
	}
	if strings.TrimSpace(payload.CNonce) == "" {
		return "", errors.New("nonce endpoint response contains no c_nonce")
	}
	return payload.CNonce, nil
}

func validateCredentialTimes(claims map[string]any, now time.Time) error {
	if exp, ok := numericDate(claims["exp"]); ok && !now.Before(exp) {
		return errors.New("issued credential is expired")
	}
	if nbf, ok := numericDate(claims["nbf"]); ok && now.Add(30*time.Second).Before(nbf) {
		return errors.New("issued credential is not yet valid")
	}
	vc := mapValue(claims["vc"])
	if vc == nil {
		vc = claims
	}
	if s, _ := vc["validFrom"].(string); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err != nil || now.Add(30*time.Second).Before(t) {
			return errors.New("issued credential validFrom is invalid or in the future")
		}
	}
	if s, _ := vc["validUntil"].(string); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err != nil || !now.Before(t) {
			return errors.New("issued credential validUntil is invalid or expired")
		}
	}
	return nil
}

func safeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if forbiddenIP(ip.IP) && !config.CurrentCredentialRetrievalConfig.DisableTLS {
			return nil, fmt.Errorf("refusing private/local address %s", ip.IP)
		}
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, network, net.JoinHostPort(host, port))
}

func validateRemoteURI(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("URI must be an absolute URL without userinfo")
	}
	if u.Fragment != "" {
		return errors.New("URI fragments are not allowed")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return errors.New("URI must use https")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil && forbiddenIP(ip) && !allowHTTP {
		return errors.New("URI points to a private/local address")
	}
	return nil
}

func forbiddenIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

func sameOrigin(rawURL, issuer string) bool {
	u, err1 := url.Parse(rawURL)
	i, err2 := url.Parse(issuer)
	return err1 == nil && err2 == nil && strings.EqualFold(u.Scheme, i.Scheme) && strings.EqualFold(u.Host, i.Host)
}

func decodeJWT(compact string) (map[string]any, map[string]any, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("JWT must have three segments")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("decode JWT header: %w", err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("decode JWT header JSON: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, nil, fmt.Errorf("decode JWT claims JSON: %w", err)
	}
	return header, claims, nil
}

func decodeJWTClaims(compact string) (map[string]any, error) {
	_, claims, err := decodeJWT(compact)
	return claims, err
}

func credentialIssuerBound(claims map[string]any, credentialIssuer, expected string) bool {
	if credentialIssuer == expected {
		return true
	}
	if v, _ := claims["credential_issuer"].(string); v == expected {
		return true
	}
	if vc := mapValue(claims["vc"]); vc != nil {
		if v, _ := vc["credential_issuer"].(string); v == expected {
			return true
		}
	}
	// For did:web, bind the DID host to the credential issuer host.
	if strings.HasPrefix(credentialIssuer, "did:web:") {
		u, err := url.Parse(expected)
		if err == nil {
			parts := strings.Split(strings.TrimPrefix(credentialIssuer, "did:web:"), ":")
			h, _ := url.PathUnescape(parts[0])
			if !strings.EqualFold(h, u.Hostname()) {
				return false
			}
			expectedPath := strings.Trim(u.Path, "/")
			didPath := strings.Join(parts[1:], "/")
			return expectedPath == didPath
		}
	}
	return false
}

func issuerFromClaims(claims map[string]any) string {
	if s, _ := claims["iss"].(string); s != "" {
		return s
	}
	vc := mapValue(claims["vc"])
	if vc == nil {
		vc = claims
	}
	if s, _ := vc["issuer"].(string); s != "" {
		return s
	}
	if m := mapValue(vc["issuer"]); m != nil {
		if s, _ := m["id"].(string); s != "" {
			return s
		}
	}
	return ""
}

func audienceMatches(v any, expected string) bool {
	if expected == "" {
		return true
	}
	switch a := v.(type) {
	case string:
		return a == expected
	case []any:
		for _, x := range a {
			if s, _ := x.(string); s == expected {
				return true
			}
		}
	}
	return false
}
func numericDate(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0).UTC(), true
	case json.Number:
		i, e := n.Int64()
		return time.Unix(i, 0).UTC(), e == nil
	case int64:
		return time.Unix(n, 0).UTC(), true
	case int:
		return time.Unix(int64(n), 0).UTC(), true
	}
	return time.Time{}, false
}
func mapValue(v any) map[string]any { m, _ := v.(map[string]any); return m }
func nestedMap(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		if v := mapValue(m[k]); v != nil {
			return v
		}
	}
	return nil
}
func stringValue(m map[string]any, keys ...string) (string, bool) {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s, true
		}
	}
	return "", false
}
func stringSliceValue(m map[string]any, keys ...string) []string {
	for _, k := range keys {
		if a, ok := m[k].([]any); ok {
			out := []string{}
			for _, v := range a {
				if s, ok := v.(string); ok {
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
		if a, ok := m[k].([]string); ok && len(a) > 0 {
			return a
		}
	}
	return nil
}
func stringOrEmpty(v any) string { s, _ := v.(string); return s }
func asMap(v any) (map[string]any, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	var m map[string]any
	e = json.Unmarshal(b, &m)
	return m, e
}
