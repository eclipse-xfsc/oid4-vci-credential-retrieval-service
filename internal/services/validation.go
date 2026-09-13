package services

import (
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
)

const (
	maxRemoteDocumentSize = 2 << 20 // 2 MiB
	maxStatusListSize     = 16 << 20
)

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
	header, claims, _, _, err := parseCompactJWT(compact)
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

// ValidateCredentialResponse validates every immediately issued JWT VC / SD-JWT VC
// before it is persisted. Deferred responses are returned to the caller without storage.
func ValidateCredentialResponse(ctx context.Context, response *credential.CredentialResponse, expectedCredentialIssuer string) error {
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
		var compact string
		if err := json.Unmarshal(item.Credential, &compact); err != nil || strings.TrimSpace(compact) == "" {
			return fmt.Errorf("credential[%d]: wallet verification currently requires a compact JWT or SD-JWT credential", i)
		}
		issuerJWT := strings.Split(compact, "~")[0]
		header, claims, signingInput, signature, err := parseCompactJWT(issuerJWT)
		if err != nil {
			return fmt.Errorf("credential[%d]: parse issued credential: %w", i, err)
		}
		issuer := issuerFromClaims(claims)
		if issuer == "" {
			return fmt.Errorf("credential[%d]: issued credential has no issuer", i)
		}
		if err := verifyJWTSignature(ctx, issuerJWT, header, claims, signingInput, signature, issuer); err != nil {
			return fmt.Errorf("credential[%d]: verify issued credential signature: %w", i, err)
		}
		if err := validateCredentialTimes(claims, time.Now().UTC()); err != nil {
			return fmt.Errorf("credential[%d]: %w", i, err)
		}
		if expectedCredentialIssuer != "" && !credentialIssuerBound(claims, issuer, expectedCredentialIssuer) {
			return fmt.Errorf("credential[%d]: issued credential issuer %q is not bound to credential issuer %q", i, issuer, expectedCredentialIssuer)
		}
		if err := validateCredentialStatus(ctx, claims, issuer); err != nil {
			return fmt.Errorf("credential[%d]: %w", i, err)
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

func validateCredentialStatus(ctx context.Context, claims map[string]any, credentialIssuer string) error {
	vc := mapValue(claims["vc"])
	if vc == nil {
		vc = claims
	}
	if raw, ok := vc["credentialStatus"]; ok {
		entries := statusEntries(raw)
		for _, entry := range entries {
			if err := checkW3CStatus(ctx, entry, credentialIssuer); err != nil {
				return err
			}
		}
		return nil
	}

	// OAuth 2.0 Status List / JWT Status List style status claim.
	if st := mapValue(claims["status"]); st != nil {
		if ref := mapValue(st["status_list"]); ref != nil {
			return checkTokenStatusList(ctx, ref, credentialIssuer)
		}
	}
	return nil
}

func checkW3CStatus(ctx context.Context, entry map[string]any, credentialIssuer string) error {
	typ, _ := entry["type"].(string)
	if typ != "StatusList2021Entry" && typ != "BitstringStatusListEntry" {
		return fmt.Errorf("unsupported credentialStatus type %q", typ)
	}
	purpose, _ := entry["statusPurpose"].(string)
	if purpose != "revocation" && purpose != "suspension" {
		return fmt.Errorf("unsupported credential status purpose %q", purpose)
	}
	indexString, _ := entry["statusListIndex"].(string)
	idx, err := strconv.ParseUint(indexString, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid statusListIndex: %w", err)
	}
	statusURL, _ := entry["statusListCredential"].(string)
	body, contentType, err := fetchProtected(ctx, statusURL, credentialIssuer)
	if err != nil {
		return fmt.Errorf("retrieve status list: %w", err)
	}

	var listClaims map[string]any
	trimmed := strings.TrimSpace(string(body))
	if strings.Count(trimmed, ".") == 2 {
		header, claims, signingInput, signature, err := parseCompactJWT(trimmed)
		if err != nil {
			return fmt.Errorf("parse status list JWT: %w", err)
		}
		iss := issuerFromClaims(claims)
		if iss == "" {
			return errors.New("status list JWT has no issuer")
		}
		if err := verifyJWTSignature(ctx, trimmed, header, claims, signingInput, signature, iss); err != nil {
			return fmt.Errorf("verify status list JWT: %w", err)
		}
		if sub, _ := claims["sub"].(string); sub != "" && sub != statusURL {
			return errors.New("status list JWT sub does not match requested URI")
		}
		if err := validateCredentialTimes(claims, time.Now().UTC()); err != nil {
			return fmt.Errorf("status list validity: %w", err)
		}
		listClaims = claims
	} else {
		// A JSON-LD status-list credential needs Data Integrity proof verification. This
		// service intentionally refuses unsigned/unverifiable JSON rather than trusting it.
		if strings.Contains(contentType, "json") {
			return errors.New("JSON-LD status list received but Data Integrity proof verification is not available; use a signed JWT status list")
		}
		return errors.New("unsupported status list representation")
	}

	encoded, listPurpose := findEncodedList(listClaims)
	if encoded == "" {
		return errors.New("status list JWT contains no encoded list")
	}
	if listPurpose != "" && listPurpose != purpose {
		return fmt.Errorf("statusPurpose mismatch: credential=%q list=%q", purpose, listPurpose)
	}
	bits, err := decodeCompressedBitstring(encoded)
	if err != nil {
		return fmt.Errorf("decode status list: %w", err)
	}
	if idx >= uint64(len(bits))*8 {
		return errors.New("statusListIndex outside status list")
	}
	set := bits[idx/8]&(1<<uint(7-(idx%8))) != 0 // W3C lists are MSB-first.
	if set {
		return fmt.Errorf("credential is %s", map[string]string{"revocation": "revoked", "suspension": "suspended"}[purpose])
	}
	return nil
}

func checkTokenStatusList(ctx context.Context, ref map[string]any, credentialIssuer string) error {
	idx, ok := uintValue(ref["idx"])
	if !ok {
		return errors.New("status.status_list.idx is invalid")
	}
	uri, _ := ref["uri"].(string)
	body, _, err := fetchProtected(ctx, uri, credentialIssuer)
	if err != nil {
		return fmt.Errorf("retrieve token status list: %w", err)
	}
	compact := strings.TrimSpace(string(body))
	header, claims, signingInput, signature, err := parseCompactJWT(compact)
	if err != nil {
		return fmt.Errorf("parse token status list: %w", err)
	}
	iss := issuerFromClaims(claims)
	if iss == "" {
		return errors.New("token status list has no issuer")
	}
	if err := verifyJWTSignature(ctx, compact, header, claims, signingInput, signature, iss); err != nil {
		return fmt.Errorf("verify token status list: %w", err)
	}
	if sub, _ := claims["sub"].(string); sub != "" && sub != uri {
		return errors.New("token status list sub does not match requested URI")
	}
	statusList := mapValue(claims["status_list"])
	if statusList == nil {
		return errors.New("token status list misses status_list claim")
	}
	bitsPerStatus, ok := uintValue(statusList["bits"])
	if !ok || bitsPerStatus == 0 || bitsPerStatus > 8 {
		return errors.New("unsupported token status list bits value")
	}
	encoded, _ := statusList["lst"].(string)
	bits, err := decodeCompressedBitstring(encoded)
	if err != nil {
		return fmt.Errorf("decode token status list: %w", err)
	}
	startBit := idx * bitsPerStatus
	if startBit+bitsPerStatus > uint64(len(bits))*8 {
		return errors.New("token status list index outside list")
	}
	var status uint64
	for i := uint64(0); i < bitsPerStatus; i++ {
		bit := (bits[(startBit+i)/8] >> uint((startBit+i)%8)) & 1 // token lists are LSB-first.
		status |= uint64(bit) << i
	}
	if status != 0 {
		return fmt.Errorf("credential has non-valid token status %d", status)
	}
	return nil
}

func fetchProtected(ctx context.Context, rawURL, credentialIssuer string) ([]byte, string, error) {
	if err := validateRemoteURI(rawURL, config.CurrentCredentialRetrievalConfig.DisableTLS); err != nil {
		return nil, "", err
	}
	if !sameOriginOrConfigured(rawURL, credentialIssuer) {
		return nil, "", errors.New("status list origin is not bound to credential issuer")
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
			if !sameOriginOrConfigured(req.URL.String(), credentialIssuer) {
				return errors.New("redirect leaves trusted status-list origin")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/statuslist+jwt, application/jwt, application/json;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("status endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteDocumentSize+1))
	if err != nil {
		return nil, "", err
	}
	if len(body) > maxRemoteDocumentSize {
		return nil, "", errors.New("status document exceeds size limit")
	}
	return body, resp.Header.Get("Content-Type"), nil
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

func sameOriginOrConfigured(rawURL, credentialIssuer string) bool {
	u, err1 := url.Parse(rawURL)
	i, err2 := url.Parse(credentialIssuer)
	if err1 == nil && err2 == nil && strings.EqualFold(u.Scheme, i.Scheme) && strings.EqualFold(u.Host, i.Host) {
		return true
	}
	if err1 == nil && strings.HasPrefix(credentialIssuer, "did:web:") {
		parts := strings.Split(strings.TrimPrefix(credentialIssuer, "did:web:"), ":")
		if len(parts) > 0 {
			host, _ := url.PathUnescape(parts[0])
			if strings.EqualFold(u.Hostname(), host) {
				return true
			}
		}
	}
	for _, allowed := range config.CurrentCredentialRetrievalConfig.StatusListAllowedOrigins {
		a, err := url.Parse(strings.TrimSpace(allowed))
		if err == nil && strings.EqualFold(u.Scheme, a.Scheme) && strings.EqualFold(u.Host, a.Host) {
			return true
		}
	}
	return false
}

func verifyJWTSignature(ctx context.Context, compact string, header, claims map[string]any, signingInput, signature []byte, issuer string) error {
	alg, _ := header["alg"].(string)
	if alg == "" || alg == "none" || strings.HasPrefix(alg, "HS") {
		return fmt.Errorf("unsupported/unsafe JWT alg %q", alg)
	}
	keys, err := resolveVerificationKeys(ctx, issuer, header)
	if err != nil {
		return err
	}
	kid, _ := header["kid"].(string)
	var last error
	for _, raw := range keys {
		if kid != "" && raw.Kid != "" && raw.Kid != kid {
			continue
		}
		if err := verifySignature(alg, raw.Key, signingInput, signature); err == nil {
			return nil
		} else {
			last = err
		}
	}
	if last == nil {
		last = errors.New("no matching verification key")
	}
	return last
}

type verificationKey struct {
	Kid string
	Key crypto.PublicKey
}

func resolveVerificationKeys(ctx context.Context, issuer string, header map[string]any) ([]verificationKey, error) {
	// Never trust an embedded JWK from an issued credential as its own trust anchor.
	// Verification keys must be resolved from an issuer-controlled trust source.
	if mapValue(header["jwk"]) != nil {
		return nil, errors.New("embedded jwk is not accepted as an issuer trust anchor")
	}
	if _, ok := header["x5c"]; ok {
		return nil, errors.New("x5c verification requires an explicitly configured trust store")
	}
	if strings.HasPrefix(issuer, "did:web:") {
		return resolveDIDWeb(ctx, issuer)
	}
	if err := validateRemoteURI(issuer, config.CurrentCredentialRetrievalConfig.DisableTLS); err != nil {
		return nil, fmt.Errorf("cannot resolve keys for issuer %q: %w", issuer, err)
	}
	wellKnown, err := issuerWellKnown(issuer, "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	meta, err := fetchJSON(ctx, wellKnown)
	if err != nil {
		wellKnown, _ = issuerWellKnown(issuer, "/.well-known/oauth-authorization-server")
		meta, err = fetchJSON(ctx, wellKnown)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve issuer metadata: %w", err)
	}
	jwksURI, _ := meta["jwks_uri"].(string)
	if jwksURI == "" {
		return nil, errors.New("issuer metadata has no jwks_uri")
	}
	set, err := fetchJSON(ctx, jwksURI)
	if err != nil {
		return nil, err
	}
	arr, _ := set["keys"].([]any)
	return parseJWKSet(arr)
}

func resolveDIDWeb(ctx context.Context, did string) ([]verificationKey, error) {
	parts := strings.Split(strings.TrimPrefix(did, "did:web:"), ":")
	if len(parts) == 0 {
		return nil, errors.New("invalid did:web")
	}
	host, err := url.PathUnescape(parts[0])
	if err != nil {
		return nil, err
	}
	var target string
	if len(parts) == 1 {
		target = "https://" + host + "/.well-known/did.json"
	} else {
		target = "https://" + host + "/" + strings.Join(parts[1:], "/") + "/did.json"
	}
	doc, err := fetchJSON(ctx, target)
	if err != nil {
		return nil, err
	}
	methods, _ := doc["verificationMethod"].([]any)
	keys := make([]verificationKey, 0, len(methods))
	for _, m := range methods {
		mm := mapValue(m)
		if mm == nil {
			continue
		}
		j := mapValue(mm["publicKeyJwk"])
		if j == nil {
			continue
		}
		key, err := parseJWK(j)
		if err != nil {
			continue
		}
		keys = append(keys, verificationKey{Kid: stringOrEmpty(mm["id"]), Key: key})
	}
	if len(keys) == 0 {
		return nil, errors.New("did:web document contains no publicKeyJwk verification method")
	}
	return keys, nil
}

func fetchJSON(ctx context.Context, rawURL string) (map[string]any, error) {
	if err := validateRemoteURI(rawURL, config.CurrentCredentialRetrievalConfig.DisableTLS); err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: safeDialContext}, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many redirects")
		}
		return validateRemoteURI(req.URL.String(), config.CurrentCredentialRetrievalConfig.DisableTLS)
	}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteDocumentSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxRemoteDocumentSize {
		return nil, errors.New("remote JSON document exceeds size limit")
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func issuerWellKnown(issuer, wellKnown string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return "", err
	}
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	u.RawPath = ""
	u.Path = wellKnown + path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func parseJWKSet(arr []any) ([]verificationKey, error) {
	keys := make([]verificationKey, 0, len(arr))
	for _, v := range arr {
		m := mapValue(v)
		if m == nil {
			continue
		}
		k, err := parseJWK(m)
		if err != nil {
			continue
		}
		keys = append(keys, verificationKey{Kid: stringOrEmpty(m["kid"]), Key: k})
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no supported key")
	}
	return keys, nil
}

func parseJWK(m map[string]any) (crypto.PublicKey, error) {
	switch stringOrEmpty(m["kty"]) {
	case "RSA":
		n, err := decodeBigInt(stringOrEmpty(m["n"]))
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(stringOrEmpty(m["e"]))
		if err != nil {
			return nil, err
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		if e == 0 {
			return nil, errors.New("invalid RSA exponent")
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case "EC":
		var curve elliptic.Curve
		switch stringOrEmpty(m["crv"]) {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, errors.New("unsupported EC curve")
		}
		x, err := decodeBigInt(stringOrEmpty(m["x"]))
		if err != nil {
			return nil, err
		}
		y, err := decodeBigInt(stringOrEmpty(m["y"]))
		if err != nil {
			return nil, err
		}
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("EC JWK point is not on curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case "OKP":
		if stringOrEmpty(m["crv"]) != "Ed25519" {
			return nil, errors.New("unsupported OKP curve")
		}
		x, err := base64.RawURLEncoding.DecodeString(stringOrEmpty(m["x"]))
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, errors.New("unsupported JWK kty")
	}
}

func verifySignature(alg string, key crypto.PublicKey, input, sig []byte) error {
	var digest []byte
	var hash crypto.Hash
	switch alg {
	case "ES256", "RS256", "PS256":
		h := sha256.Sum256(input)
		digest = h[:]
		hash = crypto.SHA256
	case "ES384", "RS384", "PS384":
		h := sha512.Sum384(input)
		digest = h[:]
		hash = crypto.SHA384
	case "ES512", "RS512", "PS512":
		h := sha512.Sum512(input)
		digest = h[:]
		hash = crypto.SHA512
	case "EdDSA":
		k, ok := key.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(k, input, sig) {
			return errors.New("EdDSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported signature algorithm %q", alg)
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(alg, "PS") {
			return rsa.VerifyPSS(k, hash, digest, sig, nil)
		}
		return rsa.VerifyPKCS1v15(k, hash, digest, sig)
	case *ecdsa.PublicKey:
		sz := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != sz*2 {
			return errors.New("invalid ECDSA signature size")
		}
		r := new(big.Int).SetBytes(sig[:sz])
		s := new(big.Int).SetBytes(sig[sz:])
		if !ecdsa.Verify(k, digest, r, s) {
			return errors.New("ECDSA signature verification failed")
		}
		return nil
	default:
		return errors.New("JWT algorithm and key type do not match")
	}
}

func parseCompactJWT(compact string) (map[string]any, map[string]any, []byte, []byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, nil, nil, nil, errors.New("JWT must have three segments")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var h, p map[string]any
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, nil, nil, nil, err
	}
	if err := json.Unmarshal(pb, &p); err != nil {
		return nil, nil, nil, nil, err
	}
	return h, p, []byte(parts[0] + "." + parts[1]), sig, nil
}

func decodeCompressedBitstring(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if strings.HasPrefix(encoded, "u") {
		encoded = strings.TrimPrefix(encoded, "u")
	}
	compressed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		if b, e := base64.StdEncoding.DecodeString(encoded); e == nil {
			compressed = b
		} else {
			return nil, err
		}
	}
	if len(compressed) == 0 {
		return nil, errors.New("empty encoded list")
	}
	var r io.ReadCloser
	if gz, e := gzip.NewReader(strings.NewReader(string(compressed))); e == nil {
		r = gz
	} else if zr, e := zlib.NewReader(strings.NewReader(string(compressed))); e == nil {
		r = zr
	} else {
		return nil, errors.New("status list is neither gzip nor zlib compressed")
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, maxStatusListSize+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxStatusListSize {
		return nil, errors.New("expanded status list exceeds size limit")
	}
	return out, nil
}

func findEncodedList(claims map[string]any) (string, string) {
	candidates := []map[string]any{claims, mapValue(claims["credentialSubject"])}
	if vc := mapValue(claims["vc"]); vc != nil {
		candidates = append(candidates, vc, mapValue(vc["credentialSubject"]))
	}
	for _, c := range candidates {
		if c == nil {
			continue
		}
		if e, _ := c["encodedList"].(string); e != "" {
			p, _ := c["statusPurpose"].(string)
			return e, p
		}
		if sl := mapValue(c["status_list"]); sl != nil {
			if e, _ := sl["lst"].(string); e != "" {
				return e, ""
			}
		}
	}
	return "", ""
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
func uintValue(v any) (uint64, bool) {
	switch n := v.(type) {
	case float64:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	case string:
		u, e := strconv.ParseUint(n, 10, 64)
		return u, e == nil
	case json.Number:
		u, e := strconv.ParseUint(n.String(), 10, 64)
		return u, e == nil
	}
	return 0, false
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
func statusEntries(v any) []map[string]any {
	if m := mapValue(v); m != nil {
		return []map[string]any{m}
	}
	if a, ok := v.([]any); ok {
		out := []map[string]any{}
		for _, x := range a {
			if m := mapValue(x); m != nil {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}
func decodeBigInt(s string) (*big.Int, error) {
	b, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil {
		return nil, e
	}
	if len(b) == 0 {
		return nil, errors.New("empty integer")
	}
	return new(big.Int).SetBytes(b), nil
}
