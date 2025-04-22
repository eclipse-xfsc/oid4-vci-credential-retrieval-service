package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/eclipse-xfsc/cloud-event-provider"
	logPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	retrieval "github.com/eclipse-xfsc/nats-message-library"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/services"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/types"
)

func handleMessage(event event.Event) {
	log := common.GetEnvironment().GetLogger()
	if event.Type() == retrieval.EventTypeRetrievalExternal {

		var newOffering retrieval.RetrievalOffering
		err := json.Unmarshal(event.Data(), &newOffering)
		if err != nil {
			log.Error(err, fmt.Sprintf("error occured while unmarshal offering %v", event))
			return
		}

		services.ProcessOffering(newOffering.TenantId, newOffering.RequestId, newOffering.GroupId, newOffering.Offer)
	}

	if event.Type() == retrieval.EventTypeRetrievalAcceptanceNotification {

		var acceptance retrieval.RetrievalAcceptanceNotification
		err := json.Unmarshal(event.Data(), &acceptance)
		if err != nil {
			log.Error(err, fmt.Sprintf("error occured while unmarshal offering %v", event))
			return
		}

		log.Info(fmt.Sprintf("new offering received: %v", acceptance))

		services.ClearOffering(acceptance.TenantId, acceptance.RequestId, acceptance.GroupId, types.Acceptance{
			Accept:          acceptance.Result,
			HolderKey:       acceptance.HolderKey,
			HolderNamespace: acceptance.HolderNamespace,
			HolderGroup:     acceptance.GroupId,
			TxCode:          acceptance.TxCode,
		}, context.Background())
	}
}

func CreateOtherClients() error {
	return services.CreatePublicationClient()
}

func StartMessageSubscription(log *logPkg.Logger) *cloudeventprovider.CloudEventProviderClient {
	log.Info("start messaging!", "url", config.CurrentCredentialRetrievalConfig.Nats.Url)

	client, err := cloudeventprovider.New(cloudeventprovider.Config{
		Protocol: cloudeventprovider.ProtocolTypeNats,
		Settings: cloudeventprovider.NatsConfig{
			Url:          config.CurrentCredentialRetrievalConfig.Nats.Url,
			QueueGroup:   config.CurrentCredentialRetrievalConfig.Nats.QueueGroup,
			TimeoutInSec: config.CurrentCredentialRetrievalConfig.Nats.TimeoutInSec,
		},
	}, cloudeventprovider.ConnectionTypeSub, config.CurrentCredentialRetrievalConfig.OfferingTopic)
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	go func() {
		err := client.SubCtx(context.Background(), handleMessage)
		if err != nil {
			log.Error(err, "")
			os.Exit(1)
		} else {
			log.Info("subscription handled")
		}
	}()
	return client
}
