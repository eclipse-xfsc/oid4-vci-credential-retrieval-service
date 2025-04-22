package services

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/eclipse-xfsc/cloud-event-provider"
	ctxPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/ctx"
	logPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	"github.com/eclipse-xfsc/nats-message-library"
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/types"
	"github.com/eclipse-xfsc/ssi-jwt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

var log logPkg.Logger

func EncryptResponse(response credential.CredentialResponse, pub jwk.Key) *jwe.Message {
	byteArray, err := json.Marshal(response.Credential)
	if err != nil {
		log.Error(err, "Failed to serialized Response")
	}
	message := jwt.EncryptJweMessage(byteArray, jwa.ECDH_ES_A256KW, pub)
	return message
}

func StoreCredential(tenantId, requestId, groupId string, response credential.CredentialResponse, pub jwk.Key, ctx context.Context) error {
	log = ctxPkg.GetLogger(ctx)
	var cred = response.Credential
	var contentType = ""
	if pub != nil {
		cred = EncryptResponse(response, pub)
		contentType = "application/jose"
	}

	var byteCredential = make([]byte, 0)
	if response.Format == string(types.JWTVC) || response.Format == string(types.SDJWT) {
		byteCredential = []byte(cred.(string))
	} else {
		c, err := json.Marshal(cred)

		if err != nil {
			log.Error(err, "error in marshalling message")
			return err
		}

		byteCredential = c
	}

	storemessage := messaging.StorageServiceStoreMessage{
		Request: common.Request{
			TenantId:  tenantId,
			RequestId: requestId,
			GroupId:   groupId,
		},
		Id:          response.CNonce,
		AccountId:   groupId,
		Type:        "credential",
		Payload:     byteCredential,
		ContentType: contentType,
	}

	b, err := json.Marshal(storemessage)

	if err != nil {
		log.Error(err, "error in marshalling message")
	}

	client, err := cloudeventprovider.New(cloudeventprovider.Config{
		Protocol: cloudeventprovider.ProtocolTypeNats,
		Settings: cloudeventprovider.NatsConfig{
			Url:          config.CurrentCredentialRetrievalConfig.Nats.Url,
			QueueGroup:   config.CurrentCredentialRetrievalConfig.Nats.QueueGroup,
			TimeoutInSec: config.CurrentCredentialRetrievalConfig.Nats.TimeoutInSec,
		},
	}, cloudeventprovider.ConnectionTypePub, config.CurrentCredentialRetrievalConfig.StoringTopic)

	if err != nil {
		log.Error(err, err.Error())
	}

	event, err := cloudeventprovider.NewEvent("retrieval-service", messaging.StoreCredentialType, b)
	if err != nil {
		log.Error(err, err.Error())
	}

	if err = client.PubCtx(ctx, event); err != nil {
		log.Error(err, fmt.Sprintf("sending event failed: %s", err))
	}
	return err
}
