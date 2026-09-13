package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	logPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	retrieval "github.com/eclipse-xfsc/nats-message-library"
	"github.com/eclipse-xfsc/nats-message-library/common"
	cmn "github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/opa"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/types"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/helper"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/oauth"
	"github.com/google/uuid"
)

func ProcessOffering(tenantId string, requestId string, groupId string, offering credential.CredentialOffer) error {
	log := cmn.GetEnvironment().GetLogger()
	log.Debug(fmt.Sprintf("new offering received: %v", offering))

	newCredentialOfferObject, err := offering.GetOfferParameters()
	if err != nil {
		log.Error(err, "error occured while getting credentialOfferObject:")
		return err
	}

	log.Debug(fmt.Sprintf("credentialOfferObject retieved: %v", newCredentialOfferObject))

	// Validate the issuer URI before metadata discovery. The offer is untrusted input,
	// so network access must not happen before URI/SSRF checks have passed.
	if err := ValidateCredentialIssuerURI(newCredentialOfferObject); err != nil {
		return errors.Join(errors.New("wallet validation rejected credential issuer URI"), err)
	}

	if config.CurrentCredentialRetrievalConfig.OfferingPolicy != "" {
		b, err := opa.GetPolicyResult(config.CurrentCredentialRetrievalConfig.OfferingPolicy, tenantId, *newCredentialOfferObject)

		if err != nil {
			log.Error(err, "error while getting result from opa policy")
			return err
		}

		if !b {
			log.Info("opa denied to process credential")
			return errors.New("opa denied")
		}
	}

	meta, err := getIssuerMetadata(newCredentialOfferObject, log)
	if err != nil {
		return err
	}

	if err := ValidateOffering(newCredentialOfferObject, meta); err != nil {
		return errors.Join(errors.New("wallet validation rejected credential offer"), err)
	}

	if config.CurrentCredentialRetrievalConfig.MetadataPolicy != "" {
		b, err := opa.GetPolicyResult(config.CurrentCredentialRetrievalConfig.MetadataPolicy, tenantId, *meta)

		if err != nil {
			log.Error(err, "error while getting result from opa policy")
			return err
		}

		if !b {
			log.Error(err, "opa denied to process credential")
			return errors.New("opa denied")
		}
	}

	err = StoreOffering(tenantId, types.OfferingRow{
		GroupId:   groupId,
		RequestId: requestId,
		MetaData:  *meta,
		Offering:  *newCredentialOfferObject,
	})

	if err != nil {
		log.Error(err, "error during storing")
		return err
	}

	err = notifyRetrieval(retrieval.RetrievalNotification{
		Offer: *newCredentialOfferObject,
		Request: common.Request{
			TenantId:  tenantId,
			RequestId: requestId,
			GroupId:   groupId,
		},
	})

	if err != nil {
		log.Error(err, "error during notification")
		return err
	}
	return nil
}

func getIssuerMetadata(offerObject *credential.CredentialOfferParameters, log *logPkg.Logger) (*credential.IssuerMetadata, error) {
	meta, err := offerObject.GetIssuerMetadata()

	if err != nil {
		if config.CurrentCredentialRetrievalConfig.DisableTLS {
			helper.DisableTlsVerification()
			meta, err = offerObject.GetIssuerMetadata()
		}

		if err != nil {
			log.Error(err, "error during object fetching")
			return nil, err
		}
	}
	return meta, err
}

var notifier cloudeventprovider.CloudEventProviderClient

func CreatePublicationClient() error {
	client, err := cloudeventprovider.New(cloudeventprovider.Config{
		Protocol: cloudeventprovider.ProtocolTypeNats,
		Settings: cloudeventprovider.NatsConfig{
			Url:          config.CurrentCredentialRetrievalConfig.Nats.Url,
			QueueGroup:   config.CurrentCredentialRetrievalConfig.Nats.QueueGroup,
			TimeoutInSec: config.CurrentCredentialRetrievalConfig.Nats.TimeoutInSec,
		},
	}, cloudeventprovider.ConnectionTypePub, retrieval.TopicRetrevialPublication)

	if err != nil {
		return err
	}

	notifier = *client

	return nil
}

func CreateHolderBinding(tenantId, nonce, audience string, accept types.Acceptance) (string, error) {
	client, err := cloudeventprovider.New(cloudeventprovider.Config{
		Protocol: cloudeventprovider.ProtocolTypeNats,
		Settings: cloudeventprovider.NatsConfig{
			Url:          config.CurrentCredentialRetrievalConfig.Nats.Url,
			QueueGroup:   config.CurrentCredentialRetrievalConfig.Nats.QueueGroup,
			TimeoutInSec: config.CurrentCredentialRetrievalConfig.Nats.TimeoutInSec,
		},
	}, cloudeventprovider.ConnectionTypeReq, config.CurrentCredentialRetrievalConfig.SignerTopic)

	if err != nil {
		return "", err
	}

	var p = make(map[string]interface{})
	if nonce != "" {
		p["nonce"] = nonce
	}
	p["aud"] = audience
	p["iat"] = time.Now().UTC().Unix()

	pb, err := json.Marshal(p)

	if err != nil {
		return "", err
	}

	var ph = make(map[string]interface{})
	ph["jwk"] = "jwk"
	ph["typ"] = "openid4vci-proof+jwt"

	pbh, err := json.Marshal(ph)

	if err != nil {
		return "", err
	}

	payload := retrieval.CreateTokenRequest{
		Request: common.Request{
			TenantId:  tenantId,
			RequestId: uuid.NewString(),
		},
		Namespace: accept.HolderNamespace,
		Group:     accept.HolderGroup,
		Key:       accept.HolderKey,
		Payload:   pb,
		Header:    pbh,
	}

	b, err := json.Marshal(payload)

	if err != nil {
		return "", err
	}

	event, err := cloudeventprovider.NewEvent("retrieval-service", retrieval.SignerServiceSignTokenType, b)

	if err != nil {
		return "", err
	}

	rep, err := client.RequestCtx(context.Background(), event)

	if err != nil {
		return "", err
	}
	if rep.Type() == retrieval.SignerServiceSignTokenType {
		var tok retrieval.CreateTokenReply
		err = json.Unmarshal(rep.Data(), &tok)
		if err != nil {
			return "", errors.Join(errors.New("cannot unmarshal event reply data"), err)
		}
		return string(tok.Token), err
	} else if rep.Type() == retrieval.SignerServiceErrorType {
		var data common.Reply
		err = json.Unmarshal(rep.Data(), &data)
		if err != nil {
			if err != nil {
				return "", errors.Join(errors.New("cannot unmarshal event error reply data"), err)
			}
		}
		return "", errors.Join(errors.New("error response from signer"),
			fmt.Errorf("status: %v id: %s msg: %s", data.Error.Status, data.Error.Id, data.Error.Msg),
		)
	} else {
		return "", fmt.Errorf("invalid response type received from signer. response type: %s", rep.Type())
	}
}

func notifyRetrieval(notify retrieval.RetrievalNotification) error {

	b, err := json.Marshal(notify)

	if err != nil {
		return err
	}

	event, err := cloudeventprovider.NewEvent("retrieval-service", retrieval.EventTypeRetrievalReceivedNotification, b)

	if err != nil {
		return err
	}

	err = notifier.PubCtx(context.Background(), event)

	return err
}

func fetchCredentialData(ctx context.Context, tenantId string, row types.OfferingRow, acceptance types.Acceptance) (*credential.CredentialResponse, error) {
	logger := cmn.GetEnvironment().GetLogger()
	metadata, err := getIssuerMetadata(&row.Offering, logger)
	if err != nil {
		return nil, errors.Join(errors.New("error during get issuermetadata"), err)
	}
	if len(row.Offering.CredentialConfigurationIDs) == 0 {
		return nil, errors.New("offering has no credential_configuration_ids")
	}
	if row.Offering.Grants == nil || row.Offering.Grants.AuthorizationCode != nil || row.Offering.Grants.PreAuthorizedCode == nil {
		return nil, errors.New("unsupported grant type")
	}

	configAS, err := metadata.FindFittingAuthorizationServer(oauth.PreAuthorizedCodeGrant)
	if err != nil {
		return nil, errors.Join(errors.New("error during finding authorization server"), err)
	}
	tokenOptions := oauth.TokenRequestOptions{
		PreAuthorizedCode: row.Offering.Grants.PreAuthorizedCode.PreAuthorizedCode,
		TxCode:            acceptance.TxCode,
	}
	tok, err := configAS.GetToken(oauth.PreAuthorizedCodeGrant, tokenOptions)
	if err != nil {
		return nil, errors.Join(errors.New("error during token get"), err)
	}

	credentialIssuer := metadata.CredentialIssuer
	if credentialIssuer == "" {
		return nil, errors.New("issuer metadata contains no credential_issuer")
	}

	// OID4VCI 1.0 moved c_nonce out of the Token Response. If the issuer
	// advertises a nonce_endpoint, obtain a fresh nonce there before creating
	// the key proof. Without a nonce endpoint the nonce claim is omitted.
	nonce, err := fetchCredentialNonce(ctx, metadata, credentialIssuer)
	if err != nil {
		return nil, errors.Join(errors.New("error during nonce retrieval"), err)
	}
	binding, err := CreateHolderBinding(tenantId, nonce, credentialIssuer, acceptance)
	if err != nil {
		return nil, errors.Join(errors.New("error during holder binding"), err)
	}
	if err := ValidateHolderBinding(binding, nonce, credentialIssuer); err != nil {
		return nil, errors.Join(errors.New("signer returned invalid holder proof"), err)
	}

	req := credential.CredentialRequest{
		Proofs: &credential.CredentialProofs{JWT: []string{binding}},
	}

	// OID4VCI 1.0: credential_identifier from authorization_details takes
	// precedence. Otherwise select by credential_configuration_id from offer.
	for _, detail := range tok.AuthorizationDetails {
		if len(detail.CredentialIdentifiers) > 0 {
			req.CredentialIdentifier = detail.CredentialIdentifiers[0]
			break
		}
		if req.CredentialConfigurationID == "" && detail.CredentialConfigurationID != "" {
			req.CredentialConfigurationID = detail.CredentialConfigurationID
		}
	}
	if req.CredentialIdentifier == "" && req.CredentialConfigurationID == "" {
		req.CredentialConfigurationID = row.Offering.CredentialConfigurationIDs[0]
	}
	if req.CredentialIdentifier == "" {
		if _, ok := metadata.CredentialConfigurationsSupported[req.CredentialConfigurationID]; !ok {
			return nil, fmt.Errorf("credential configuration %q is not supported by issuer metadata", req.CredentialConfigurationID)
		}
	}

	cred, err := metadata.CredentialRequest(req, *tok)
	if err != nil {
		return nil, errors.Join(errors.New("error during getting credential"), err)
	}
	if err := ValidateCredentialResponse(ctx, cred, credentialIssuer); err != nil {
		return nil, errors.Join(errors.New("wallet validation rejected issued credential"), err)
	}
	return cred, nil
}
