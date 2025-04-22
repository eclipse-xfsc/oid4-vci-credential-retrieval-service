package config

import (
	"github.com/eclipse-xfsc/cloud-event-provider"
	configPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/config"
)

type CredentialRetrievalConfig struct {
	configPkg.BaseConfig
	Country        string `mapstructure:"country" envconfig:"COUNTRY"`
	Region         string `mapstructure:"region" envconfig:"REGION"`
	OfferingTopic  string `envconfig:"OFFERING_TOPIC"`
	StoringTopic   string `envconfig:"STORING_TOPIC"`
	SignerTopic    string `envconfig:"SIGNER_TOPIC"`
	OfferingPolicy string `envconfig:"OFFERINGPOLICY"`
	MetadataPolicy string `envconfig:"METADATAPOLICY"`
	DisableTLS     bool   `envconfig:"DISABLETLS"`

	Nats      cloudeventprovider.NatsConfig `envconfig:"NATS"`
	Cassandra struct {
		Host     string `mapstructure:"host" envconfig:"HOST"`
		KeySpace string `mapstructure:"keyspace" envconfig:"KEYSPACE"`
		User     string `mapstructure:"user, omitempty" envconfig:"USER"`
		Password string `mapstructure:"password, omitempty" envconfig:"PASSWORD"`
	} `mapstructure:"cassandra" envconfig:"CASSANDRA"`
}

var CurrentCredentialRetrievalConfig CredentialRetrievalConfig

func LoadConfig() error {
	return configPkg.LoadConfig("CREDENTIALRETRIEVAL", &CurrentCredentialRetrievalConfig, getDefaults())
}

func getDefaults() map[string]any {
	return map[string]any{
		"offeringTopic": "offering",
		"storingTopic":  "storing",
		"OPAUrl":        "localhost:8181/v1/data/credential-retrieval-service/demo",
	}
}
