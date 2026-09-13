package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	cloudeventprovider "github.com/eclipse-xfsc/cloud-event-provider"
	ctxPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/ctx"
	logPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	messaging "github.com/eclipse-xfsc/nats-message-library"
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
	jwt "github.com/eclipse-xfsc/ssi-jwt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

var log logPkg.Logger

func EncryptResponse(response credential.CredentialResponse, pub jwk.Key) *jwe.Message {
	byteArray, err := json.Marshal(response.Credentials)
	if err != nil {
		log.Error(err, "Failed to serialize Response")
	}
	return jwt.EncryptJweMessage(byteArray, jwa.ECDH_ES_A256KW, pub)
}

type storageMessagePublisher interface {
	Publish(context.Context, messaging.StorageServiceStoreMessage) error
}

type natsStorageMessagePublisher struct {
	client cloudeventprovider.CloudEventProviderClient
}

func (p *natsStorageMessagePublisher) Publish(ctx context.Context, message messaging.StorageServiceStoreMessage) error {
	b, err := json.Marshal(message)
	if err != nil {
		return err
	}
	event, err := cloudeventprovider.NewEvent("retrieval-service", messaging.StoreCredentialType, b)
	if err != nil {
		return err
	}
	if err := p.client.PubCtx(ctx, event); err != nil {
		return fmt.Errorf("sending storage event failed: %w", err)
	}
	return nil
}

// newStorageMessagePublisher is replaceable in tests, keeping StoreCredential independent
// from a real NATS broker while production still uses cloud-event-provider.
var newStorageMessagePublisher = func() (storageMessagePublisher, error) {
	client, err := cloudeventprovider.New(cloudeventprovider.Config{
		Protocol: cloudeventprovider.ProtocolTypeNats,
		Settings: cloudeventprovider.NatsConfig{
			Url:          config.CurrentCredentialRetrievalConfig.Nats.Url,
			QueueGroup:   config.CurrentCredentialRetrievalConfig.Nats.QueueGroup,
			TimeoutInSec: config.CurrentCredentialRetrievalConfig.Nats.TimeoutInSec,
		},
	}, cloudeventprovider.ConnectionTypePub, config.CurrentCredentialRetrievalConfig.StoringTopic)
	if err != nil {
		return nil, err
	}
	return &natsStorageMessagePublisher{client: *client}, nil
}

// StoreCredential stores the OID4VCI 1.0 credentials array. Each credential is
// emitted as an individual storage message so batch issuance does not lose items.
func StoreCredential(tenantId, requestId, groupId string, response credential.CredentialResponse, pub jwk.Key, ctx context.Context) error {
	log = ctxPkg.GetLogger(ctx)
	if len(response.Credentials) == 0 {
		return errors.New("credential response contains no immediately issued credentials")
	}

	publisher, err := newStorageMessagePublisher()
	if err != nil {
		return err
	}

	for _, item := range response.Credentials {
		payload := []byte(item.Credential)
		contentType := "application/json"
		var compact string
		if json.Unmarshal(item.Credential, &compact) == nil && compact != "" {
			payload = []byte(compact)
			contentType = "application/vc+jwt"
		}
		if pub != nil {
			message := jwt.EncryptJweMessage(payload, jwa.ECDH_ES_A256KW, pub)
			payload, err = json.Marshal(message)
			if err != nil {
				return err
			}
			contentType = "application/jose"
		}

		storemessage := messaging.StorageServiceStoreMessage{
			Request: common.Request{TenantId: tenantId, RequestId: requestId, GroupId: groupId},
			Id:      uuid.NewString(), AccountId: groupId, Type: "credential", Payload: payload, ContentType: contentType,
		}
		if err := publisher.Publish(ctx, storemessage); err != nil {
			return err
		}
	}
	return nil
}
