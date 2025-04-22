package common

import (
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/docs"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/connection"
	ginSwagger "github.com/swaggo/gin-swagger"

	logPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
)

type Environment struct {
	session   connection.SessionInterface
	logger    *logPkg.Logger
	isHealthy bool
}

var env *Environment

func init() {
	env = new(Environment)
}

func GetEnvironment() *Environment {
	return env
}

func (e *Environment) SetSession(session connection.SessionInterface) {
	e.session = session
}

func (e *Environment) GetSession() connection.SessionInterface {
	return e.session
}

func (e *Environment) GetRegion() string {
	return config.CurrentCredentialRetrievalConfig.Region
}

func (e *Environment) GetCountry() string {
	return config.CurrentCredentialRetrievalConfig.Country
}

func (e *Environment) GetAccountPartition(account string) string {
	if len(account) < AccountPartitionLength {
		return account
	}
	return account[0:AccountPartitionLength]
}

func (e *Environment) SetLogger(logger *logPkg.Logger) {
	e.logger = logger
}

func (e *Environment) GetLogger() *logPkg.Logger { return e.logger }

func (e *Environment) SetHealthy(isHealthy bool) {
	e.isHealthy = isHealthy
}

func (e *Environment) IsHealthy() bool {
	return !e.session.Closed()
}

// SetSwaggerBasePath sets the base path that will be used by swagger ui for requests url generation
func (e *Environment) SetSwaggerBasePath(path string) {
	docs.SwaggerInfo.BasePath = path + BasePath
}

// SwaggerOptions swagger config options. See https://github.com/swaggo/gin-swagger?tab=readme-ov-file#configuration
func (e *Environment) SwaggerOptions() []func(config *ginSwagger.Config) {
	return []func(config *ginSwagger.Config){
		ginSwagger.DefaultModelsExpandDepth(10),
	}
}
