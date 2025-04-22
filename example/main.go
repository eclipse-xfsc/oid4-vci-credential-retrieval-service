package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/eclipse-xfsc/cloud-event-provider"
	messaging "github.com/eclipse-xfsc/nats-message-library"
	"github.com/eclipse-xfsc/nats-message-library/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
)

func main() {

	createCredentialClient, err := cloudeventprovider.New(
		cloudeventprovider.Config{Protocol: cloudeventprovider.ProtocolTypeNats, Settings: cloudeventprovider.NatsConfig{
			Url:          "nats://localhost:4222",
			TimeoutInSec: time.Hour,
		}},
		cloudeventprovider.ConnectionTypePub,
		"offering",
	)

	for {
		println("Take Offering Link...Press Enter")
		fmt.Scanln()
		link := "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Ftest-not.xfsc.dev%2Foid4vci%2F%22%2C%22credential_configuration_ids%22%3A%5B%22demo-sd-jwt-idm%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22eyJraWQiOiJlX2EyNTYiLCJhbGciOiJBMjU2R0NNS1ciLCJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiJWRkpUQU1tVjY3VXlIUDAtIiwidGFnIjoiMjdubmprR0RsbkxhdG9QTEM0cWlyUSJ9._WiAwdo2bawps21xfr8oJ6PwOfYX5HvRodLxewKyz90.wGm4zwPVWIAPySH3.w-AeaczfOAJhSrg0m7hlkW7TI5CvuqGQrdRtEx9YkvLPfxK02MsVDADSJQTAeCPdPj4iKWSnP5vP999BccHWtnkYHbkJXkTODzkjJpGgbz5F4TP7zspfbpDneJv0sJTDgOzA-06NnxuObRqGW19PhCzWT9k90VkYmVAv55w8n1mHO8eBPUpa5qj233bPt4UE58wJecS7g8EG5ecMUWzU3qgquPitCTjmuhUAfLom3APm1TJHDjuaVRgfNW4xrT6msSuxZgpCA23hkjET8vt8Zo5O6Y13zW-EPwL3OykrdlxeS1kKspr0tfWDoMWwV18eacD3vh0JyN3_e_riMdc5HNFMl5ashCqvJYHIPs7_ocPsosyq4pCC8zBfTrd64rlxERLEn8zjE-Tzuyakv6ZS1XUvYExuO9HbBaYOSHYJiXqclW3Qcm5Hj2hx1eKqQnfJMlg3vbugtnEwG3SxwAc3KzyFc4CRwfF-Ivz5XuEEzgIHsdrFyqwS-cuENCAB4eDbKYJjA5SoyLtRGmL6M7Geuiyqrxb7Am5X6RWVaYj3hj_57z1HtqGNXc2FLvcGlCEKZ3S6Mu7-hO4hbb-toDNMZ-JZYiA_5MnLqA7j0o-LoXMQjJX7L0Zq01ukZFB1gb6872Tkbj6FSwobwXXjW3KI8Fi-wd2ZquQ578NeYC45qZwctLYpg11oJ1OKVAtC5wU2S4ptRW9L6ChLnBMssE3gmTt5JeApVx0CS-EecKLlRLUknGPD_coU5AADHeCBqW88g1XpZfoN_YiRo9DWHS63vgCqUHsVtJcPlYhq_h8ljZEJHb1xGe4GSo_fECXd_UWv1jv7RU_O3i5Z6V9IlZDAU_Qc22GOoiD0uEc.L71Tca1f43FG41M-n03ZoA%22%2C%22interval%22%3A5%7D%7D%7D"

		if err != nil {
			panic(err)
		}

		println("Retrieve Offering")
		req := messaging.RetrievalOffering{
			Request: common.Request{
				TenantId:  "tenant_space",
				RequestId: "TestId",
			},
			Offer: credential.CredentialOffer{
				CredentialOffer: link,
			},
		}

		b, _ := json.Marshal(req)

		testEvent, _ := cloudeventprovider.NewEvent("test-issuer", messaging.EventTypeRetrievalExternal, b)
		println(messaging.EventTypeRetrievalExternal)
		err = createCredentialClient.PubCtx(context.Background(), testEvent)

		if err != nil {
			fmt.Println(err.Error())
			return
		}

		not := messaging.RetrievalAcceptanceNotification{
			Request:         req.Request,
			Message:         "Ok",
			Result:          true,
			HolderKey:       "test",
			HolderNamespace: "transit",
		}

		b, _ = json.Marshal(not)

		println("try to bind credential to transit engine and key test")

		testEvent, _ = cloudeventprovider.NewEvent("test-issuer", messaging.EventTypeRetrievalAcceptanceNotification, b)

		err = createCredentialClient.PubCtx(context.Background(), testEvent)
	}
}
