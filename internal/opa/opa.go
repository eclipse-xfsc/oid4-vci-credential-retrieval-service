package opa

import (
	"encoding/json"

	"github.com/eclipse-xfsc/oid4-vci-credential-retrieval-service/internal/common"
	"github.com/eclipse-xfsc/oid4-vci-vp-library/helper"
)

type PolicyResult struct {
	Result struct {
		Allow bool `json:"allow"`
	} `json:"result"`
}

func createBody(tenantId string, payload any) []byte {
	// Create a map to hold the JSON data
	jsonData := make(map[string]interface{})
	jsonData["tenantId"] = tenantId
	jsonData["payload"] = payload
	// Convert the map to JSON
	jsonBytes, err := json.Marshal(jsonData)
	if err != nil {
		common.GetEnvironment().GetLogger().Error(err, "error in creating body")
		return nil
	}

	return jsonBytes
}

func GetPolicyResult(url string, tenantId string, payload any) (bool, error) {
	data := createBody(tenantId, payload)

	body, err := helper.Post(url, data, helper.ApplicationJson, nil)
	if err != nil {
		common.GetEnvironment().GetLogger().Error(err, "error while post request: %v")
		return false, err
	}

	// Unmarshal OPA result response
	var result PolicyResult
	err = json.Unmarshal(body, &result)
	if err != nil {
		return false, err
	}

	return result.Result.Allow, nil
}
