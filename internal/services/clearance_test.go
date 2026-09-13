package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/connection"
	mockpkg "github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/mocks"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/types"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
)

func offeringRowValues(t *testing.T, requestID string) []interface{} {
	t.Helper()
	meta, err := json.Marshal(credential.IssuerMetadata{})
	require.NoError(t, err)
	offer, err := json.Marshal(credential.CredentialOfferParameters{})
	require.NoError(t, err)
	return []interface{}{
		requestID,
		base64.RawStdEncoding.EncodeToString(meta),
		base64.RawStdEncoding.EncodeToString(offer),
		"received",
		time.Unix(1_700_000_000, 0).UTC(),
	}
}

func setupClearanceDB(t *testing.T, requestID string) (*mockpkg.Database, *[]string) {
	t.Helper()
	oldRegion := config.CurrentCredentialRetrievalConfig.Region
	oldCountry := config.CurrentCredentialRetrievalConfig.Country
	config.CurrentCredentialRetrievalConfig.Region = "eu"
	config.CurrentCredentialRetrievalConfig.Country = "de"
	t.Cleanup(func() {
		config.CurrentCredentialRetrievalConfig.Region = oldRegion
		config.CurrentCredentialRetrievalConfig.Country = oldCountry
	})

	executed := []string{}
	db := &mockpkg.Database{}
	db.QueryFunc = func(stmt string, values ...interface{}) connection.QueryInterface {
		switch {
		case strings.Contains(stmt, "SELECT requestId"):
			return &mockpkg.Query{Rows: [][]interface{}{offeringRowValues(t, requestID)}}
		case strings.Contains(stmt, "DELETE"), strings.Contains(stmt, "UPDATE ocm.offerings SET"):
			executed = append(executed, stmt)
			return &mockpkg.Query{}
		default:
			t.Fatalf("unexpected query: %s", stmt)
			return &mockpkg.Query{}
		}
	}
	oldSession := common.GetEnvironment().GetSession()
	common.GetEnvironment().SetSession(db)
	t.Cleanup(func() { common.GetEnvironment().SetSession(oldSession) })
	return db, &executed
}

func credentialResponseFromJSON(t *testing.T, raw string) credential.CredentialResponse {
	t.Helper()
	var response credential.CredentialResponse
	require.NoError(t, json.Unmarshal([]byte(raw), &response))
	return response
}

func TestClearOfferingRejectDeletesOfferingWithoutFetchingCredential(t *testing.T) {
	_, executed := setupClearanceDB(t, "request-1")
	oldFetch := fetchCredentialDataForAcceptance
	fetchCredentialDataForAcceptance = func(context.Context, string, types.OfferingRow, types.Acceptance) (*credential.CredentialResponse, error) {
		t.Fatal("credential must not be fetched when the holder rejects the offering")
		return nil, nil
	}
	t.Cleanup(func() { fetchCredentialDataForAcceptance = oldFetch })

	response, err := ClearOffering("tenant_a", "request-1", "group-123", types.Acceptance{Accept: false}, context.Background())
	require.NoError(t, err)
	require.Nil(t, response)
	require.Len(t, *executed, 1)
	require.Contains(t, (*executed)[0], "DELETE")
}

func TestClearOfferingAcceptStoresCredentialAndMarksOfferingAccepted(t *testing.T) {
	_, executed := setupClearanceDB(t, "request-2")
	expected := credentialResponseFromJSON(t, `{"credentials":[{"credential":"header.payload.signature"}]}`)

	oldFetch := fetchCredentialDataForAcceptance
	oldStore := storeAcceptedCredential
	fetchCredentialDataForAcceptance = func(ctx context.Context, tenantID string, row types.OfferingRow, acceptance types.Acceptance) (*credential.CredentialResponse, error) {
		require.Equal(t, "tenant_a", tenantID)
		require.Equal(t, "request-2", row.RequestId)
		require.True(t, acceptance.Accept)
		return &expected, nil
	}
	stored := false
	storeAcceptedCredential = func(tenantID, requestID, groupID string, response credential.CredentialResponse, pub jwk.Key, ctx context.Context) error {
		stored = true
		require.Equal(t, "tenant_a", tenantID)
		require.Equal(t, "request-2", requestID)
		require.Equal(t, "group-123", groupID)
		require.Nil(t, pub)
		require.Len(t, response.Credentials, 1)
		return nil
	}
	t.Cleanup(func() {
		fetchCredentialDataForAcceptance = oldFetch
		storeAcceptedCredential = oldStore
	})

	response, err := ClearOffering("tenant_a", "request-2", "group-123", types.Acceptance{Accept: true}, context.Background())
	require.NoError(t, err)
	require.True(t, stored)
	require.Same(t, &expected, response)
	require.Len(t, *executed, 1)
	require.Contains(t, (*executed)[0], "status=?")
}

func TestClearOfferingAcceptDoesNotMarkAcceptedWhenStorageFails(t *testing.T) {
	_, executed := setupClearanceDB(t, "request-3")
	expected := credentialResponseFromJSON(t, `{"credentials":[{"credential":"header.payload.signature"}]}`)
	oldFetch := fetchCredentialDataForAcceptance
	oldStore := storeAcceptedCredential
	fetchCredentialDataForAcceptance = func(context.Context, string, types.OfferingRow, types.Acceptance) (*credential.CredentialResponse, error) {
		return &expected, nil
	}
	storeAcceptedCredential = func(string, string, string, credential.CredentialResponse, jwk.Key, context.Context) error {
		return errors.New("nats unavailable")
	}
	t.Cleanup(func() {
		fetchCredentialDataForAcceptance = oldFetch
		storeAcceptedCredential = oldStore
	})

	response, err := ClearOffering("tenant_a", "request-3", "group-123", types.Acceptance{Accept: true}, context.Background())
	require.Nil(t, response)
	require.ErrorContains(t, err, "failed to store accepted credential")
	require.Empty(t, *executed, "status must remain unchanged when storage publication fails")
}

func TestStoreOfferingPersistsReceivedStatusUsingDatabaseAdapter(t *testing.T) {
	oldRegion := config.CurrentCredentialRetrievalConfig.Region
	oldCountry := config.CurrentCredentialRetrievalConfig.Country
	config.CurrentCredentialRetrievalConfig.Region = "eu"
	config.CurrentCredentialRetrievalConfig.Country = "de"
	t.Cleanup(func() {
		config.CurrentCredentialRetrievalConfig.Region = oldRegion
		config.CurrentCredentialRetrievalConfig.Country = oldCountry
	})

	db := &mockpkg.Database{}
	var statement string
	var values []interface{}
	db.QueryFunc = func(stmt string, bound ...interface{}) connection.QueryInterface {
		statement = stmt
		values = append([]interface{}(nil), bound...)
		return &mockpkg.Query{}
	}
	oldSession := common.GetEnvironment().GetSession()
	common.GetEnvironment().SetSession(db)
	t.Cleanup(func() { common.GetEnvironment().SetSession(oldSession) })

	offering := types.OfferingRow{GroupId: "group-123", RequestId: "request-4"}
	err := StoreOffering("tenant_a", offering)
	require.NoError(t, err)
	require.Contains(t, statement, "status='received'")
	require.Contains(t, statement, "UPDATE ocm.offerings")
	require.Len(t, values, 8)
	require.Equal(t, "group-123", values[6])
	require.Equal(t, "request-4", values[7])
}
