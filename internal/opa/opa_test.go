package opa

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/stretchr/testify/require"
)

type mockResponse struct {
	Result struct {
		AcceptCredentials bool `json:"accept_credentials"`
	} `json:"result"`
}

type mockBody struct {
	Input struct {
		TenantId         string        `json:"tenant_id"`
		CredentialIssuer string        `json:"credential_issuer"`
		Credentials      []interface{} `json:"credentials"`
		Grants           struct {
			AuthorizationCode struct {
				IssuerState string `json:"issuer_state"`
			} `json:"authorization_code"`
			PreAuthorizedCode struct {
				Code        string `json:"pre-authorized_code"`
				PinRequired bool   `json:"user_pin_required"`
			} `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code"`
		} `json:"grants"`
	} `json:"input"`
}

func startMockServer(t *testing.T) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Fatalf("Expected method 'POST', got '%s'", req.Method)
		}

		if err := mockOPABehavior(w, req); err != nil {
			t.Fatal(err)
		}
	}))

	return server
}

func mockOPABehavior(w http.ResponseWriter, req *http.Request) error {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}

	var reqBody mockBody
	if err := json.Unmarshal(body, &reqBody); err != nil {
		return err
	}

	var response mockResponse
	response.Result.AcceptCredentials = reqBody.Input.TenantId == "foo"

	data, err := json.Marshal(response)
	if err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
}

func TestAcceptCredentials(t *testing.T) {
	server := startMockServer(t)
	defer server.Close()

	config.CurrentCredentialRetrievalConfig.OfferingPolicy = server.URL

	mockOffer := credential.CredentialOfferParameters{}
	mockOffer.CredentialIssuer = "hydra"
	mockOffer.Credentials = []string{"VerifiableCredential", "UniversityDegreeCredential"}
	mockOffer.Grants.AuthorizationCode.IssuerState = "eyJhbGciOiJSU0EtFYUaBy"
	mockOffer.Grants.PreAuthorizedCode.PreAuthorizationCode = "AOIPO235"

	acceptCredentials, _ := GetPolicyResult(config.CurrentCredentialRetrievalConfig.OfferingPolicy, "foo", mockOffer)
	require.Equal(t, acceptCredentials, true)
	acceptCredentials, _ = GetPolicyResult(config.CurrentCredentialRetrievalConfig.OfferingPolicy, "bar", mockOffer)
	require.Equal(t, acceptCredentials, false)
}
