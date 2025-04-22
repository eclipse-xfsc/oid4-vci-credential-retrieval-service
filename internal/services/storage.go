package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/types"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/gocql/gocql"
)

func StoreOffering(tenantId string, offering types.OfferingRow) error {
	session := common.GetEnvironment().GetSession()
	country := common.GetEnvironment().GetCountry()
	region := common.GetEnvironment().GetRegion()
	partition := common.GetEnvironment().GetAccountPartition(offering.GroupId)
	queryString := fmt.Sprintf(`UPDATE %s.offerings SET 
			last_update_timestamp=toTimestamp(now()),
			type=?,
			metadata=?,
			offerParams=?,
			status='received'
		    WHERE
				partition=? AND
				region=? AND
				country=? AND
				groupId=? AND
				requestId=?;`, tenantId)

	bMeta, err := json.Marshal(offering.MetaData)

	if err != nil {
		return err
	}

	bOffer, err := json.Marshal(offering.Offering)

	if err != nil {
		return err
	}

	return session.Query(queryString,
		strings.Join(offering.Offering.Credentials, ","),
		base64.RawStdEncoding.EncodeToString(bMeta),
		base64.RawStdEncoding.EncodeToString(bOffer),
		partition,
		region,
		country,
		offering.GroupId, offering.RequestId).WithContext(context.Background()).Exec()
}

func GetOfferings(tenantId string, groupId string) ([]types.OfferingRow, error) {
	queryString := fmt.Sprintf(`SELECT requestId,metadata,offerParams,status,last_update_timestamp FROM %s.offerings WHERE partition=? AND 
																					region=? AND 
																					country=? AND 
																					groupId=?;`, tenantId)
	return getOfferings(tenantId, groupId, queryString)
}

func ClearOffering(tenantId string, requestId string, groupId string, acceptance types.Acceptance, ctx context.Context) (*credential.CredentialResponse, error) {

	queryString := fmt.Sprintf(`SELECT requestId,metadata,offerParams,status,last_update_timestamp FROM %s.offerings WHERE partition=? AND 
																					region=? AND 
																					country=? AND 
																					groupId=? AND
																					requestId='%s';`, tenantId, requestId)
	//set status in table to rejected accepted, if accepted send message to storage service

	offs, err := getOfferings(tenantId, groupId, queryString)

	if err != nil {
		return nil, err
	}

	if len(offs) == 0 {
		return nil, errors.New("no record found")
	}

	response, err := fetchCredentialData(tenantId, offs[0], acceptance)

	if err != nil {
		return nil, err
	}

	if acceptance.Accept {
		err = StoreCredential(tenantId, requestId, groupId, *response, nil, ctx)
		if err != nil {
			return nil, errors.Join(errors.New("failed to store accepted credential"), err)
		}
		err = updateOfferingStatus(tenantId, requestId, groupId, acceptance.Accept, ctx)
		if err != nil {
			return nil, errors.Join(errors.New("failed to update offering status"), err)
		}
	} else {
		err = deleteRejectedOffering(tenantId, requestId, groupId, ctx)
		if err != nil {
			return nil, errors.Join(errors.New("failed to delete rejected offering"), err)
		}
	}

	return response, nil
}

func deleteRejectedOffering(tenantId string, requestId string, groupId string, ctx context.Context) error {
	queryString := fmt.Sprintf(`
			DELETE
			FROM %s.offerings
			WHERE
			    partition = ? AND
			    region = ? AND
			    country = ? AND
			    groupid = ? AND
			    requestid = ?;`,
		tenantId,
	)
	session := common.GetEnvironment().GetSession()
	country := common.GetEnvironment().GetCountry()
	region := common.GetEnvironment().GetRegion()
	partition := common.GetEnvironment().GetAccountPartition(groupId)

	return session.Query(queryString, partition, region, country, groupId, requestId).WithContext(ctx).Exec()
}

func updateOfferingStatus(tenantId string, requestId string, groupId string, accept bool, ctx context.Context) error {
	var status string
	if accept {
		status = "accepted"
	} else {
		status = "rejected"
	}

	queryString := fmt.Sprintf(`
			UPDATE %s.offerings SET
			status=?
			WHERE
			    partition = ? AND
			    region = ? AND
			    country = ? AND
			    groupid = ? AND
			    requestid = ?;`,
		tenantId,
	)
	session := common.GetEnvironment().GetSession()
	country := common.GetEnvironment().GetCountry()
	region := common.GetEnvironment().GetRegion()
	partition := common.GetEnvironment().GetAccountPartition(groupId)

	return session.Query(queryString, status, partition, region, country, groupId, requestId).WithContext(ctx).Exec()
}

func getOfferings(tenantId string, groupId string, queryString string) ([]types.OfferingRow, error) {
	session := common.GetEnvironment().GetSession()
	country := common.GetEnvironment().GetCountry()
	region := common.GetEnvironment().GetRegion()
	partition := common.GetEnvironment().GetAccountPartition(groupId)

	var requestId string
	var metadata string
	var offerParams string
	var status string
	var last_update_timestamp time.Time

	query := session.Query(queryString,
		partition,
		region,
		country,
		groupId).Consistency(gocql.LocalQuorum).Raw().Iter()

	ret := make([]types.OfferingRow, 0)

	for query.Scan(&requestId, &metadata, &offerParams, &status, &last_update_timestamp) {
		off, err := buildOfferingRow(groupId, requestId, last_update_timestamp, status, metadata, offerParams)

		if err != nil {
			return nil, err
		}

		ret = append(ret, *off)
	}

	if err := query.Close(); err != nil {
		return nil, err
	}
	return ret, nil
}

func buildOfferingRow(groupId string, requestId string, last_update_timestamp time.Time, status string, metadata string, offerParams string) (*types.OfferingRow, error) {
	off := types.OfferingRow{
		GroupId:   groupId,
		RequestId: requestId,
		TimeStamp: last_update_timestamp,
		Status:    status,
	}

	bMeta, err := base64.RawStdEncoding.DecodeString(metadata)

	if err != nil {
		return nil, err
	}

	bOffer, err := base64.RawStdEncoding.DecodeString(offerParams)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(bMeta, &off.MetaData)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(bOffer, &off.Offering)

	if err != nil {
		return nil, err
	}
	return &off, nil
}
