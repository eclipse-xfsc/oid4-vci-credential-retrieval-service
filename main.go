package main

import (
	"context"
	"fmt"
	"log"

	ctxPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/ctx"
	logPkg "github.com/eclipse-xfsc/microservice-core-go/pkg/logr"
	"github.com/eclipse-xfsc/microservice-core-go/pkg/server"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/config"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/connection"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/messaging"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/rest"
	"github.com/gin-gonic/gin"
	"github.com/kelseyhightower/envconfig"
)

func startDbConnection(logger *logPkg.Logger) error {
	// Establish connections
	dbSession, err := connection.Connection(logger)
	if err != nil {
		logger.Error(err, "Can not connect to db")
		common.GetEnvironment().SetSession(dbSession)
		return err
	} else {
		logger.Info("Database connected")
	}
	return nil
}

// @title			Credential retrieval service API
// @version		1.0
// @description	Service for handling credentials retrieval
// @license.name	Apache 2.0
// @license.url	http://www.apache.org/licenses/LICENSE-2.0.html
// @host			localhost:8080

func main() {

	ctx := context.Background()
	if err := envconfig.Process("CREDENTIALRETRIEVAL", &config.CurrentCredentialRetrievalConfig); err != nil {
		panic(fmt.Sprintf("failed to load config from env: %+v", err))
	}

	logger, err := logPkg.New(config.CurrentCredentialRetrievalConfig.LogLevel, config.CurrentCredentialRetrievalConfig.IsDev, nil)
	if err != nil {
		log.Fatalf("failed to init logger: %v", err)
	}

	ctx = ctxPkg.WithLogger(ctx, *logger)

	common.GetEnvironment().SetLogger(logger)

	session, err := connection.Connection(logger)

	if err != nil {
		log.Fatalf("failed to init session", err)
	}

	common.GetEnvironment().SetSession(session)

	brokerClient := messaging.StartMessageSubscription(logger)
	defer brokerClient.Close()

	err = messaging.CreateOtherClients()

	if err != nil {
		log.Fatalf("failed to init messaging", err)
	}

	srv := server.New(common.GetEnvironment(), config.CurrentCredentialRetrievalConfig.ServerMode)
	srv.SetHealthHandler(func(ctx *gin.Context) {
		if session.Closed() {
			ctx.AbortWithStatus(400)
		} else {
			ctx.AbortWithStatus(200)
		}
	})

	srv.Add(func(tenantsGrp *gin.RouterGroup) {
		grp := tenantsGrp.Group(common.BasePath)
		grp.GET("/list/:groupId", rest.HandleGetOffering)
		grp.PUT("/retrieve/:groupId", rest.HandleRetrieval)
		grp.DELETE("/clear/:groupId/:requestId", rest.HandleClearance)
	})

	err = srv.Run(config.CurrentCredentialRetrievalConfig.ListenPort)

	if err != nil {
		log.Fatalf("failed to init logger: %v", err)
	}
}
