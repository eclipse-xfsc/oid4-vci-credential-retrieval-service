package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/types"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/gocql/gocql"
)

const selectOfferingsQuery = `
	SELECT requestId,
	       metadata,
	       offerParams,
	       status,
	       last_update_timestamp
	FROM ocm.offerings
	WHERE partition = ?
	  AND region = ?
	  AND country = ?
	  AND groupId = ?
	  AND tenantId = ?;`

const selectOfferingByRequestIDQuery = `
	SELECT requestId,
	       metadata,
	       offerParams,
	       status,
	       last_update_timestamp
	FROM ocm.offerings
	WHERE partition = ?
	  AND region = ?
	  AND country = ?
	  AND groupId = ?
	  AND tenantId = ?
	  AND requestId = ?;`

func StoreOffering(tenantId string, offering types.OfferingRow) error {
	if tenantId == "" {
		return errors.New("tenantId must not be empty")
	}

	if offering.GroupId == "" {
		return errors.New("groupId must not be empty")
	}

	if offering.RequestId == "" {
		return errors.New("requestId must not be empty")
	}

	session := common.GetEnvironment().GetSession()
	country := common.GetEnvironment().GetCountry()
	region := common.GetEnvironment().GetRegion()
	partition := common.GetEnvironment().GetAccountPartition(offering.GroupId)

	slog.Info(
		"storing offering",
		"tenantId", tenantId,
		"groupId", offering.GroupId,
		"requestId", offering.RequestId,
		"partition", partition,
		"region", region,
		"country", country,
		"credentialConfigurationIDs", offering.Offering.CredentialConfigurationIDs,
	)

	queryString := `
		UPDATE ocm.offerings
		SET last_update_timestamp = toTimestamp(now()),
		    type = ?,
		    metadata = ?,
		    offerParams = ?,
		    status = 'received'
		WHERE partition = ?
		  AND region = ?
		  AND country = ?
		  AND groupId = ?
		  AND tenantId = ?
		  AND requestId = ?;`

	bMeta, err := json.Marshal(offering.MetaData)
	if err != nil {
		slog.Error(
			"failed to marshal offering metadata",
			"tenantId", tenantId,
			"groupId", offering.GroupId,
			"requestId", offering.RequestId,
			"error", err,
		)
		return fmt.Errorf("failed to marshal offering metadata: %w", err)
	}

	bOffer, err := json.Marshal(offering.Offering)
	if err != nil {
		slog.Error(
			"failed to marshal offering",
			"tenantId", tenantId,
			"groupId", offering.GroupId,
			"requestId", offering.RequestId,
			"error", err,
		)
		return fmt.Errorf("failed to marshal offering: %w", err)
	}

	err = session.Query(
		queryString,
		strings.Join(offering.Offering.CredentialConfigurationIDs, ","),
		base64.RawStdEncoding.EncodeToString(bMeta),
		base64.RawStdEncoding.EncodeToString(bOffer),
		partition,
		region,
		country,
		offering.GroupId,
		tenantId,
		offering.RequestId,
	).WithContext(context.Background()).Exec()

	if err != nil {
		slog.Error(
			"failed to store offering",
			"tenantId", tenantId,
			"groupId", offering.GroupId,
			"requestId", offering.RequestId,
			"partition", partition,
			"region", region,
			"country", country,
			"error", err,
		)
		return fmt.Errorf("failed to store offering: %w", err)
	}

	slog.Info(
		"offering stored successfully",
		"tenantId", tenantId,
		"groupId", offering.GroupId,
		"requestId", offering.RequestId,
	)

	return nil
}

func GetOfferings(tenantId string, groupId string) ([]types.OfferingRow, error) {
	if tenantId == "" {
		return nil, errors.New("tenantId must not be empty")
	}

	if groupId == "" {
		return nil, errors.New("groupId must not be empty")
	}

	slog.Debug(
		"fetching offerings",
		"tenantId", tenantId,
		"groupId", groupId,
	)

	offerings, err := getOfferings(
		tenantId,
		groupId,
		"",
		selectOfferingsQuery,
	)

	if err != nil {
		slog.Error(
			"failed to fetch offerings",
			"tenantId", tenantId,
			"groupId", groupId,
			"error", err,
		)
		return nil, err
	}

	slog.Info(
		"offerings fetched",
		"tenantId", tenantId,
		"groupId", groupId,
		"count", len(offerings),
	)

	return offerings, nil
}

// Injectable seams keep the clearance workflow testable without an issuer,
// signer NATS, or storage NATS connection.
// Production defaults point at the real implementations.
var fetchCredentialDataForAcceptance = fetchCredentialData
var storeAcceptedCredential = StoreCredential

func ClearOffering(
	tenantId string,
	requestId string,
	groupId string,
	acceptance types.Acceptance,
	ctx context.Context,
) (*credential.CredentialResponse, error) {

	if tenantId == "" {
		return nil, errors.New("tenantId must not be empty")
	}

	if groupId == "" {
		return nil, errors.New("groupId must not be empty")
	}

	if requestId == "" {
		return nil, errors.New("requestId must not be empty")
	}

	slog.Info(
		"clearing offering",
		"tenantId", tenantId,
		"groupId", groupId,
		"requestId", requestId,
		"accept", acceptance.Accept,
	)

	offs, err := getOfferings(
		tenantId,
		groupId,
		requestId,
		selectOfferingByRequestIDQuery,
	)
	if err != nil {
		slog.Error(
			"failed to fetch offering for clearance",
			"tenantId", tenantId,
			"groupId", groupId,
			"requestId", requestId,
			"error", err,
		)
		return nil, fmt.Errorf("failed to fetch offering: %w", err)
	}

	if len(offs) == 0 {
		slog.Warn(
			"offering not found",
			"tenantId", tenantId,
			"groupId", groupId,
			"requestId", requestId,
		)
		return nil, errors.New("no record found")
	}

	if len(offs) > 1 {
		slog.Warn(
			"multiple offerings found for request",
			"tenantId", tenantId,
			"groupId", groupId,
			"requestId", requestId,
			"count", len(offs),
		)
	}

	if !acceptance.Accept {
		slog.Info(
			"offering rejected, deleting offering",
			"tenantId", tenantId,
			"groupId", groupId,
			"requestId", requestId,
		)

		if err := deleteRejectedOffering(
			tenantId,
			requestId,
			groupId,
			ctx,
		); err != nil {
			slog.Error(
				"failed to delete rejected offering",
				"tenantId", tenantId,
				"groupId", groupId,
				"requestId", requestId,
				"error", err,
			)

			return nil, errors.Join(
				errors.New("failed to delete rejected offering"),
				err,
			)
		}

		slog.Info(
			"rejected offering deleted",
			"tenantId", tenantId,
			"groupId", groupId,
			"requestId", requestId,
		)

		return nil, nil
	}

	slog.Debug(
		"fetching credential data for accepted offering",
		"tenantId", tenantId,
		"groupId", groupId,
		"requestId", requestId,
	)

	response, err := fetchCredentialDataForAcceptance(
		ctx,
		tenantId,
		groupId,
		offs[0],
		acceptance,
	)
	if err != nil {
		slog.Error(
			"failed to fetch credential data",
			"tenantId", tenantId,
			"groupId", groupId,
			"requestId", requestId,
			"error", err,
		)

		return nil, fmt.Errorf(
			"failed to fetch credential data for accepted offering: %w",
			err,
		)
	}

	if response == nil {
		slog.Error(
			"credential response is nil",
			"tenantId", tenantId,
			"groupId", groupId,
			"requestId", requestId,
		)

		return nil, errors.New("credential response is nil")
	}

	slog.Debug(
		"storing accepted credential",
		"tenantId", tenantId,
		"groupId", groupId,
		"requestId", requestId,
	)

	err = storeAcceptedCredential(
		tenantId,
		requestId,
		groupId,
		*response,
		nil,
		ctx,
	)
	if err != nil {
		slog.Error(
			"failed to store accepted credential",
			"tenantId", tenantId,
			"groupId", groupId,
			"requestId", requestId,
			"error", err,
		)

		return nil, errors.Join(
			errors.New("failed to store accepted credential"),
			err,
		)
	}

	slog.Debug(
		"updating offering status to accepted",
		"tenantId", tenantId,
		"groupId", groupId,
		"requestId", requestId,
	)

	err = updateOfferingStatus(
		tenantId,
		requestId,
		groupId,
		true,
		ctx,
	)
	if err != nil {
		slog.Error(
			"failed to update offering status",
			"tenantId", tenantId,
			"groupId", groupId,
			"requestId", requestId,
			"error", err,
		)

		return nil, errors.Join(
			errors.New("failed to update offering status"),
			err,
		)
	}

	slog.Info(
		"offering accepted successfully",
		"tenantId", tenantId,
		"groupId", groupId,
		"requestId", requestId,
	)

	return response, nil
}

func deleteRejectedOffering(
	tenantId string,
	requestId string,
	groupId string,
	ctx context.Context,
) error {

	if tenantId == "" {
		return errors.New("tenantId must not be empty")
	}

	if groupId == "" {
		return errors.New("groupId must not be empty")
	}

	if requestId == "" {
		return errors.New("requestId must not be empty")
	}

	queryString := `
		DELETE FROM ocm.offerings
		WHERE partition = ?
		  AND region = ?
		  AND country = ?
		  AND groupId = ?
		  AND tenantId = ?
		  AND requestId = ?;`

	session := common.GetEnvironment().GetSession()
	country := common.GetEnvironment().GetCountry()
	region := common.GetEnvironment().GetRegion()
	partition := common.GetEnvironment().GetAccountPartition(groupId)

	slog.Debug(
		"deleting rejected offering",
		"tenantId", tenantId,
		"groupId", groupId,
		"requestId", requestId,
		"partition", partition,
		"region", region,
		"country", country,
	)

	err := session.Query(
		queryString,
		partition,
		region,
		country,
		groupId,
		tenantId,
		requestId,
	).WithContext(ctx).Exec()

	if err != nil {
		slog.Error(
			"database error while deleting rejected offering",
			"tenantId", tenantId,
			"groupId", groupId,
			"requestId", requestId,
			"partition", partition,
			"error", err,
		)

		return fmt.Errorf("failed to delete offering from database: %w", err)
	}

	return nil
}

func updateOfferingStatus(
	tenantId string,
	requestId string,
	groupId string,
	accept bool,
	ctx context.Context,
) error {

	if tenantId == "" {
		return errors.New("tenantId must not be empty")
	}

	if groupId == "" {
		return errors.New("groupId must not be empty")
	}

	if requestId == "" {
		return errors.New("requestId must not be empty")
	}

	status := "rejected"
	if accept {
		status = "accepted"
	}

	queryString := `
		UPDATE ocm.offerings
		SET status = ?
		WHERE partition = ?
		  AND region = ?
		  AND country = ?
		  AND groupId = ?
		  AND tenantId = ?
		  AND requestId = ?;`

	session := common.GetEnvironment().GetSession()
	country := common.GetEnvironment().GetCountry()
	region := common.GetEnvironment().GetRegion()
	partition := common.GetEnvironment().GetAccountPartition(groupId)

	slog.Debug(
		"updating offering status",
		"tenantId", tenantId,
		"groupId", groupId,
		"requestId", requestId,
		"status", status,
		"partition", partition,
		"region", region,
		"country", country,
	)

	err := session.Query(
		queryString,
		status,
		partition,
		region,
		country,
		groupId,
		tenantId,
		requestId,
	).WithContext(ctx).Exec()

	if err != nil {
		slog.Error(
			"database error while updating offering status",
			"tenantId", tenantId,
			"groupId", groupId,
			"requestId", requestId,
			"status", status,
			"partition", partition,
			"error", err,
		)

		return fmt.Errorf("failed to update offering status: %w", err)
	}

	return nil
}

func getOfferings(
	tenantId string,
	groupId string,
	requestId string,
	queryString string,
) ([]types.OfferingRow, error) {

	if tenantId == "" {
		return nil, errors.New("tenantId must not be empty")
	}

	if groupId == "" {
		return nil, errors.New("groupId must not be empty")
	}

	session := common.GetEnvironment().GetSession()
	country := common.GetEnvironment().GetCountry()
	region := common.GetEnvironment().GetRegion()
	partition := common.GetEnvironment().GetAccountPartition(groupId)

	slog.Debug(
		"executing offering query",
		"tenantId", tenantId,
		"groupId", groupId,
		"requestId", requestId,
		"partition", partition,
		"region", region,
		"country", country,
	)

	args := []interface{}{
		partition,
		region,
		country,
		groupId,
		tenantId,
	}

	if requestId != "" {
		args = append(args, requestId)
	}

	iter := session.Query(
		queryString,
		args...,
	).Consistency(gocql.LocalQuorum).Iter()

	ret := make([]types.OfferingRow, 0)

	var (
		rowRequestId        string
		metadata            string
		offerParams         string
		status              string
		lastUpdateTimestamp time.Time
	)

	for iter.Scan(
		&rowRequestId,
		&metadata,
		&offerParams,
		&status,
		&lastUpdateTimestamp,
	) {
		slog.Debug(
			"offering row fetched",
			"tenantId", tenantId,
			"groupId", groupId,
			"requestId", rowRequestId,
			"status", status,
			"lastUpdateTimestamp", lastUpdateTimestamp,
		)

		off, err := buildOfferingRow(
			groupId,
			rowRequestId,
			lastUpdateTimestamp,
			status,
			metadata,
			offerParams,
		)
		if err != nil {
			slog.Error(
				"failed to build offering row",
				"tenantId", tenantId,
				"groupId", groupId,
				"requestId", rowRequestId,
				"error", err,
			)

			// Close the iterator before returning so driver-side
			// resources are released even on decode errors.
			if closeErr := iter.Close(); closeErr != nil {
				return nil, errors.Join(
					fmt.Errorf("failed to build offering row: %w", err),
					fmt.Errorf("failed to close offering iterator: %w", closeErr),
				)
			}

			return nil, fmt.Errorf("failed to build offering row: %w", err)
		}

		ret = append(ret, *off)
	}

	if err := iter.Close(); err != nil {
		slog.Error(
			"offering query failed",
			"tenantId", tenantId,
			"groupId", groupId,
			"requestId", requestId,
			"partition", partition,
			"region", region,
			"country", country,
			"error", err,
		)

		return nil, fmt.Errorf("failed to execute offering query: %w", err)
	}

	slog.Debug(
		"offering query completed",
		"tenantId", tenantId,
		"groupId", groupId,
		"requestId", requestId,
		"count", len(ret),
	)

	return ret, nil
}

func buildOfferingRow(
	groupId string,
	requestId string,
	lastUpdateTimestamp time.Time,
	status string,
	metadata string,
	offerParams string,
) (*types.OfferingRow, error) {

	off := types.OfferingRow{
		GroupId:   groupId,
		RequestId: requestId,
		TimeStamp: lastUpdateTimestamp,
		Status:    status,
	}

	bMeta, err := base64.RawStdEncoding.DecodeString(metadata)
	if err != nil {
		slog.Error(
			"failed to decode offering metadata",
			"groupId", groupId,
			"requestId", requestId,
			"error", err,
		)

		return nil, fmt.Errorf("failed to decode offering metadata: %w", err)
	}

	bOffer, err := base64.RawStdEncoding.DecodeString(offerParams)
	if err != nil {
		slog.Error(
			"failed to decode offering parameters",
			"groupId", groupId,
			"requestId", requestId,
			"error", err,
		)

		return nil, fmt.Errorf("failed to decode offering parameters: %w", err)
	}

	if err := json.Unmarshal(bMeta, &off.MetaData); err != nil {
		slog.Error(
			"failed to unmarshal offering metadata",
			"groupId", groupId,
			"requestId", requestId,
			"error", err,
		)

		return nil, fmt.Errorf("failed to unmarshal offering metadata: %w", err)
	}

	if err := json.Unmarshal(bOffer, &off.Offering); err != nil {
		slog.Error(
			"failed to unmarshal offering parameters",
			"groupId", groupId,
			"requestId", requestId,
			"error", err,
		)

		return nil, fmt.Errorf("failed to unmarshal offering parameters: %w", err)
	}

	return &off, nil
}
