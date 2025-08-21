package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/services"
	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/types"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/model/credential"
)

// HandleGetOffering godoc
// @Summary Get offerings
// @Description get offerings by tenantId and groupId
// @Tags offerings
// @Accept  json
// @Produce  json
// @Param tenantId path string true "Tenant ID"
// @Param groupId path string true "Group ID"
// @Success 200 {array} types.OfferingRow
// @Router /list/{groupId} [get]
func HandleGetOffering(ctx *gin.Context) {
	log := common.GetEnvironment().GetLogger()

	tenantId, ok := ctx.Params.Get("tenantId")

	if !ok {
		log.Error(errors.New("no tenant id found"), "no tenant id found")
		ctx.AbortWithStatus(400)
		return
	}

	groupId, ok := ctx.Params.Get("groupId")

	if !ok {
		log.Error(errors.New("no group id found"), "no group id found")
		ctx.AbortWithStatus(400)
		return
	}

	offers, err := services.GetOfferings(tenantId, groupId)

	if err != nil {
		log.Error(err, "no group id found")
		ctx.AbortWithStatus(400)
		return
	}

	ctx.JSON(200, offers)
}

// HandleRetrieval godoc
// @Summary Handle retrieval
// @Description handle retrieval by tenantId and groupId
// @Tags retrieval
// @Accept  json
// @Produce  json
// @Param tenantId path string true "Tenant ID"
// @Param groupId path string true "Group ID"
// @Param offering body credential.CredentialOffer true "Offering"
// @Success 200 "ID of created offering request"
// @Router /retrieve/{groupId} [put]
func HandleRetrieval(ctx *gin.Context) {
	log := common.GetEnvironment().GetLogger()

	tenantId, ok := ctx.Params.Get("tenantId")

	if !ok {
		ctx.AbortWithStatus(400)
		return
	}

	groupId, ok := ctx.Params.Get("groupId")

	if !ok {
		ctx.AbortWithStatus(400)
		return
	}

	b, err := io.ReadAll(ctx.Request.Body)

	if err != nil {
		ctx.AbortWithError(400, err)
		return
	}

	var newOffering credential.CredentialOffer
	err = json.Unmarshal(b, &newOffering)
	if err != nil {
		log.Error(err, fmt.Sprintf("error occured while unmarshal offering %v", b))
		ctx.AbortWithError(400, err)
		return
	}
	requestId := uuid.NewString()
	err = services.ProcessOffering(tenantId, requestId, groupId, newOffering)

	if err != nil {
		ctx.AbortWithError(400, err)
		return
	}
	ctx.JSON(200, requestId)
}

// HandleClearance godoc
// @Summary Handle clearance
// @Description handle clearance by tenantId, groupId and requestId
// @Tags clearance
// @Accept  json
// @Produce  json
// @Param tenantId path string true "Tenant ID"
// @Param groupId path string true "Group ID"
// @Param requestId path string true "Request ID"
// @Param acceptance body types.Acceptance true "Acceptance"
// @Success 200 {object} credential.CredentialResponse
// @Router /clear/{groupId}/{requestId} [delete]
func HandleClearance(ctx *gin.Context) {
	log := common.GetEnvironment().GetLogger()

	tenantId, ok := ctx.Params.Get("tenantId")

	if !ok {
		log.Error(errors.New("no tenant id found"), "no tenant id found")
		ctx.JSON(400, "no tenant id found")
		return
	}

	groupId, ok := ctx.Params.Get("groupId")

	if !ok {
		log.Error(errors.New("no group id found"), "no group id found")
		ctx.JSON(400, "no group id found")
		return
	}

	requestId, ok := ctx.Params.Get("requestId")

	if !ok {
		log.Error(errors.New("no group id found"), "no group id found")
		ctx.JSON(400, "no request id found")
		return
	}

	b, err := io.ReadAll(ctx.Request.Body)

	if err != nil {
		ctx.JSON(400, err.Error())
		return
	}

	var accept types.Acceptance
	err = json.Unmarshal(b, &accept)
	if err != nil {
		log.Error(err, fmt.Sprintf("error occured while unmarshal offering %v", b))
		ctx.JSON(400, err.Error())
		return
	}

	resp, err := services.ClearOffering(tenantId, requestId, groupId, accept, ctx.Request.Context())
	
	if err != nil {
	    log.Error(err, "error occurred while clearing offering")
	    ctx.JSON(400, gin.H{"error": err.Error()})
	    return
	}

	ctx.JSON(200, resp)
}
