# OID4VCI / OID4VP Library

Go models and helpers used by XFSC services for **OpenID for Verifiable Credential Issuance (OpenID4VCI)** and **OpenID for Verifiable Presentations (OpenID4VP)** flows.

The current `oidvci10` branch contains the OpenID4VCI 1.0 model updates. It replaces the previous README statement that described the library as a partial Draft 13 implementation.

> **Note:** OpenID4VCI 1.0 support is actively evolving. The library also keeps selected legacy fields for interoperability with wallet implementations that still use older request structures. Consumers should prefer the 1.0 structures documented below.

## Requirements

- Go 1.24+
- The module currently declares the Go 1.24.2 toolchain.

```bash
go get github.com/eclipse-xfsc/oid4-vci-vp-library
```

## OpenID4VCI 1.0 support

### Credential Offer

The credential offer model uses the OpenID4VCI 1.0 fields:

- `credential_issuer`
- `credential_configuration_ids`
- `authorization_code`
- `urn:ietf:params:oauth:grant-type:pre-authorized_code`
- `tx_code`
- optional `authorization_server`

`CredentialOfferParameters.Validate()` checks required values, duplicate configuration IDs, pre-authorized code presence and `tx_code` constraints.

```go
offer := credential.CredentialOfferParameters{
    CredentialIssuer: "https://issuer.example.com",
    CredentialConfigurationIDs: []string{"UniversityDegreeCredential"},
}

link, err := offer.CreateOfferLink()
if err != nil {
    // handle error
}
```

The library can parse both an embedded `credential_offer` and a referenced `credential_offer_uri` through `CredentialOffer.GetOfferParameters()`.

### Credential Issuer Metadata

`credential.IssuerMetadata` models the OpenID4VCI issuer metadata, including:

- `credential_issuer`
- `authorization_servers`
- `credential_endpoint`
- `nonce_endpoint`
- `deferred_credential_endpoint`
- `notification_endpoint`
- `credential_configurations_supported`
- credential request/response encryption metadata
- batch credential issuance metadata
- signed metadata

Credential configurations support format-specific data such as `vct`, credential definitions, claims, display information, cryptographic binding methods, signing algorithms and proof types.

### Authorization Details and Token Response

The OAuth models support `authorization_details` with `type=openid_credential`, including:

- `credential_configuration_id`
- `credential_identifiers`
- `claims`
- `locations`

The token helper currently supports the pre-authorized code grant and `tx_code`.

### Credential Request

For OpenID4VCI 1.0, credential selection is represented by exactly one of:

- `credential_identifier`
- `credential_configuration_id`

Proofs use the plural `proofs` structure:

```json
{
  "credential_identifier": "credential-1",
  "proofs": {
    "jwt": ["eyJ..."]
  }
}
```

The model supports the proof variants:

- `jwt`
- `di_vp`
- `attestation`

```go
request := credential.CredentialRequest{
    CredentialIdentifier: "credential-1",
    Proofs: &credential.CredentialProofs{
        JWT: []string{signedProof},
    },
}
```

The older singular `proof` and `format` fields remain in `CredentialRequest` only for interoperability with legacy wallet implementations. `CredentialRequest.Normalize()` converts a supported legacy JWT proof into the OpenID4VCI 1.0 `proofs` representation. New integrations should use `proofs` directly.

### JWT Key Proof validation

JWT key proofs use `typ=openid4vci-proof+jwt`. The proof validation implementation covers the protocol-relevant checks represented by the library, including:

- supported proof type and signing algorithm
- JWT proof signature validation
- audience binding
- issued-at (`iat`) validation
- optional issuer (`iss`)
- nonce validation when a Nonce Endpoint is used
- proof key material supplied through the supported JOSE header mechanisms

Proof algorithms are constrained by the selected credential configuration's `proof_types_supported` metadata.

### Nonce Endpoint support

Issuer metadata exposes `nonce_endpoint`. The library provides helpers for creating and validating opaque HMAC-SHA256 protected nonces:

```go
nonce, err := credential.CreateNonce(
    nonceSecret,
    tenantID,
    credential.DefaultNonceTTL,
)
```

`ValidateNonce()` checks integrity, tenant binding and expiration.

The nonce helper requires a secret of at least 32 characters. The generated nonce contains a random JTI and expiration. Applications requiring strict one-time use must additionally persist and consume the JTI server-side; cryptographic validation alone does not provide replay protection.

### Credential Response

The OpenID4VCI response model supports:

- immediate issuance through `credentials`
- deferred issuance through `transaction_id`
- `interval`
- `notification_id`
- JSON-string and JSON-object credential values

Relevant protocol error values include `invalid_credential_request`, `unknown_credential_configuration`, `unknown_credential_identifier`, `invalid_proof`, `invalid_nonce`, `invalid_encryption_parameters`, `credential_request_denied` and `invalid_transaction_id`.

## OpenID4VP support

The library also contains OpenID4VP / Presentation Exchange related models and helpers under `model/presentation`, including:

- request objects
- presentation definitions
- presentation submissions
- `vp_token` response parameters
- `direct_post` and `direct_post.jwt` response modes
- credential filtering against presentation definitions

This area is separate from the OpenID4VCI 1.0 work described above. Do not interpret the OpenID4VCI 1.0 branch designation as a claim that every OpenID4VP feature or newer OpenID4VP profile is fully implemented.

## Package overview

```text
config/                 default library configuration
helper/                 HTTP request helpers
model/credential/       OID4VCI offers, metadata, requests and responses
model/oauth/            OAuth authorization server and authorization_details models
model/token/            token response models
model/presentation/     OID4VP / Presentation Exchange models
model/types/            shared credential/presentation formats and response types
```

## Security considerations

Protocol models are not a replacement for wallet or issuer trust validation. Applications using this library remain responsible for applying the security policy required by their role.

In particular, wallet implementations should validate issued credentials before storing or presenting them. Depending on the credential format this includes signature/proof verification, issuer trust and issuer binding, validity periods, holder/key binding where applicable, and credential status/revocation information.

Remote URIs obtained from credential offers, issuer metadata, presentation requests, status information or other untrusted protocol input must not be fetched blindly. Services should apply HTTPS requirements, URI validation, redirect restrictions, response size/time limits and SSRF protections appropriate to their deployment.

Issuer implementations must validate credential requests and key proofs against the selected credential configuration and must not treat a syntactically valid proof as sufficient authorization to issue a credential.

`helper.DisableTlsVerification()` disables TLS certificate verification globally for the default HTTP transport. It is intended only for controlled development/test environments and must not be enabled in production.

## Interoperability

Some compatibility fields intentionally remain in the models for wallets that have not yet migrated completely to OpenID4VCI 1.0. Compatibility input should be normalized at the protocol boundary and the 1.0 representation should be used internally wherever possible.

When adding new protocol functionality, prefer the final OpenID4VCI 1.0 field names and structures instead of extending legacy Draft-based representations.

## Development

Run the test suite with:

```bash
go test ./...
```

Format changes before committing:

```bash
gofmt -w .
```

## License

See [LICENSE](LICENSE).
