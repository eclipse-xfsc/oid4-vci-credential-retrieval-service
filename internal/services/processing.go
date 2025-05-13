package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/eclipse-xfsc/cloud-event-provider"
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

	if config.CurrentCredentialRetrievalConfig.MetadataPolicy != "" {
		b, err := opa.GetPolicyResult(config.CurrentCredentialRetrievalConfig.OfferingPolicy, tenantId, *meta)

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
	p["nonce"] = nonce
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
			fmt.Errorf("status: %s id: %s msg: %s", data.Error.Status, data.Error.Id, data.Error.Msg),
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

func fetchCredentialData(tenantId string, row types.OfferingRow, acceptance types.Acceptance) (*credential.CredentialResponse, error) {
	logger := cmn.GetEnvironment().GetLogger()
	metadata, err := getIssuerMetadata(&row.Offering, logger)

	if err != nil {
		log.Error(err, "error during get issuermetadata")
		return nil, errors.Join(errors.New("error during get issuermetadata"), err)
	}

	if row.Offering.Grants.AuthorizationCode != nil || row.Offering.Grants.PreAuthorizedCode == nil {
		return nil, errors.Join(errors.New("unsupported grant type"), err)
	}

	//Here should be a better check, but ok for now
	config, err := metadata.FindFittingAuthorizationServer(oauth.PreAuthorizedCodeGrant)

	if err != nil {
		log.Error(err, "error during finding authorization server")
		return nil, errors.Join(errors.New("error during get error during finding authorization server"), err)
	}

	options := make(map[string]interface{}, 0)
	options["code"] = row.Offering.Grants.PreAuthorizedCode.PreAuthorizationCode
	options["interval"] = row.Offering.Grants.PreAuthorizedCode.Interval
	if acceptance.TxCode != "" {
		options["tx_code"] = acceptance.TxCode
	}

	tok, err := config.GetToken(oauth.PreAuthorizedCodeGrant, options)

	if err != nil {
		log.Error(err, "error during token get")
		return nil, errors.Join(errors.New("error during token get"), err)
	}

	binding, err := CreateHolderBinding(tenantId, tok.CNonce, config.Issuer, acceptance)

	if err != nil {
		log.Error(err, "error during holder binding")
		return nil, errors.Join(errors.New("error during holder binding"), err)
	}

	req := credential.CredentialRequest{
		Proof: &credential.Proof{
			ProofType: credential.ProofTypeJWT,
			Jwt:       &binding,
		},
	}

	if tok.AuthorizationDetails != nil {
		req.CredentialIdentifier = tok.AuthorizationDetails.CredentialIdentifiers[0]
	} else {
		credConfig := row.MetaData.CredentialConfigurationsSupported[row.Offering.Credentials[0]]
		req.Format = credConfig.Format
		if credConfig.Vct != nil {
			req.Vct = credConfig.Vct
		}

		if credConfig.Claims != nil {
			req.Claims = credConfig.Claims
		}

		if credConfig.Order != nil {
			req.Order = credConfig.Order
		}
	}

	cred, err := metadata.CredentialRequest(req, *tok)
	if err != nil {
		log.Error(err, "error during getting credential")
		return nil, errors.Join(errors.New("error during getting credential"), err)
	}
	cred.Format = metadata.CredentialConfigurationsSupported[row.Offering.Credentials[0]].Format
	return cred, nil
}
