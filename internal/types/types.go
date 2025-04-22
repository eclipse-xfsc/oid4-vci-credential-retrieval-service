package types

import (
	"time"

	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
)

type OfferingRow struct {
	GroupId   string                               `json:"groupId"`
	RequestId string                               `json:"requestId"`
	MetaData  credential.IssuerMetadata            `json:"metadata"`
	Offering  credential.CredentialOfferParameters `json:"offering"`
	Status    string                               `json:"status"`
	TimeStamp time.Time                            `json:"timestamp"`
}

type Acceptance struct {
	Accept          bool   `json:"accept"`
	EncryptionKey   []byte `json:"encryptionKey,omitempty"`
	HolderKey       string `json:"holderKey"`
	HolderNamespace string `json:"holderNamespace"`
	HolderGroup     string `json:"holderGroup"`
	TxCode          string `json:"tx_code"`
}
