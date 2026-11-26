package backend

import (
	"fmt"
	"io"
	"net/http"

	"encoding/json"

	"github.com/free-ran-ue/free-ran-ue/v2/console/model"
	"github.com/free-ran-ue/free-ran-ue/v2/constant"
	"github.com/free-ran-ue/util"
	"github.com/gin-gonic/gin"
)

func (cs *console) handleConsoleGnbInfo(c *gin.Context) {
	if err := authticate(c, cs.jwt.secret); err != nil {
		cs.AuthLog.Warnln(err)
		c.JSON(http.StatusUnauthorized, model.ConsoleGnbInfoResponse{
			Message: err.Error(),
		})
		return
	}

	var request model.ConsoleGnbInfoRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		cs.GnbLog.Warnf("Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, model.ConsoleGnbInfoResponse{
			Message: "Failed to bind JSON",
		})
		return
	}

	uri := fmt.Sprintf("http://%s:%d%s", request.Ip, request.Port, constant.API_REQUEST_GNB_INFO)

	response, err := util.SendHttpRequest(uri, constant.API_REQUEST_GNB_INFO_METHOD, nil, nil)
	if err != nil {
		cs.GnbLog.Warnln(err)
		c.JSON(http.StatusInternalServerError, model.ConsoleGnbInfoResponse{
			Message: err.Error(),
		})
		return
	}

	for key, values := range response.Headers {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	c.Data(response.StatusCode, constant.APPLICATION_JSON, response.Body)
}

func (cs *console) handleConsoleGnbUeNrdcModify(c *gin.Context) {
	if err := authticate(c, cs.jwt.secret); err != nil {
		cs.AuthLog.Warnln(err)
		c.JSON(http.StatusUnauthorized, model.ConsoleGnbUeNrdcModifyResponse{
			Message: err.Error(),
		})
		return
	}

	var request model.ConsoleGnbUeNrdcModifyRequest
	rawBody, err := io.ReadAll(c.Request.Body)
	if err != nil {
		cs.GnbLog.Warnf("Failed to read body: %v", err)
		c.JSON(http.StatusBadRequest, model.ConsoleGnbUeNrdcModifyResponse{
			Message: fmt.Sprintf("Failed to read body: %v", err),
		})
		return
	}

	if err := json.Unmarshal(rawBody, &request); err != nil {
		cs.GnbLog.Warnf("Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, model.ConsoleGnbUeNrdcModifyResponse{
			Message: fmt.Sprintf("Failed to bind JSON: %v", err),
		})
		return
	}

	uri := fmt.Sprintf("http://%s:%d%s", request.Ip, request.Port, constant.API_REQUEST_GNB_UE_NRDC)

	response, err := util.SendHttpRequest(uri, constant.API_REQUEST_GNB_UE_NRDC_METHOD, nil, rawBody)
	if err != nil {
		cs.GnbLog.Warnln(err)
		c.JSON(http.StatusInternalServerError, model.ConsoleGnbUeNrdcModifyResponse{
			Message: err.Error(),
		})
		return
	}

	for key, values := range response.Headers {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	c.Data(response.StatusCode, constant.APPLICATION_JSON, response.Body)
}

func (cs *console) fetchGnbInfo(ip string, port int) (*model.GnbInfo, error) {
	uri := fmt.Sprintf("http://%s:%d%s", ip, port, constant.API_REQUEST_GNB_INFO)

	response, err := util.SendHttpRequest(uri, constant.API_REQUEST_GNB_INFO_METHOD, nil, nil)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gNB %s:%d info returned status %d", ip, port, response.StatusCode)
	}

	var info model.ConsoleGnbInfoResponse
	if err := json.Unmarshal(response.Body, &info); err != nil {
		return nil, fmt.Errorf("failed to decode gNB %s:%d info: %v", ip, port, err)
	}
	return &info.GnbInfo, nil
}

func validateHandoverTarget(source, target *model.GnbInfo) error {
	if source.GnbId == target.GnbId {
		return fmt.Errorf("target gNB is the same as the source gNB")
	}
	if !source.XnInterface.Enable {
		return fmt.Errorf("xn interface is not enabled on source gNB %s", source.GnbName)
	}
	if !target.XnInterface.Enable {
		return fmt.Errorf("xn interface is not enabled on target gNB %s", target.GnbName)
	}
	if source.XnInterface.DialIp != target.XnInterface.ListenIp || source.XnInterface.DialPort != target.XnInterface.ListenPort {
		return fmt.Errorf("target gNB %s (Xn %s:%d) is not the Xn peer of source gNB %s (Xn peer %s:%d)",
			target.GnbName, target.XnInterface.ListenIp, target.XnInterface.ListenPort,
			source.GnbName, source.XnInterface.DialIp, source.XnInterface.DialPort)
	}
	return nil
}

func (cs *console) handleConsoleGnbUeHandover(c *gin.Context) {
	if err := authticate(c, cs.jwt.secret); err != nil {
		cs.AuthLog.Warnln(err)
		c.JSON(http.StatusUnauthorized, model.ConsoleGnbUeHandoverResponse{
			Message: err.Error(),
		})
		return
	}

	var request model.ConsoleGnbUeHandoverRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		cs.GnbLog.Warnf("Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, model.ConsoleGnbUeHandoverResponse{
			Message: fmt.Sprintf("Failed to bind JSON: %v", err),
		})
		return
	}

	sourceInfo, err := cs.fetchGnbInfo(request.Ip, request.Port)
	if err != nil {
		cs.GnbLog.Warnln(err)
		c.JSON(http.StatusInternalServerError, model.ConsoleGnbUeHandoverResponse{
			Message: fmt.Sprintf("Failed to get source gNB info: %v", err),
		})
		return
	}
	targetInfo, err := cs.fetchGnbInfo(request.TargetIp, request.TargetPort)
	if err != nil {
		cs.GnbLog.Warnln(err)
		c.JSON(http.StatusInternalServerError, model.ConsoleGnbUeHandoverResponse{
			Message: fmt.Sprintf("Failed to get target gNB info: %v", err),
		})
		return
	}
	if err := validateHandoverTarget(sourceInfo, targetInfo); err != nil {
		cs.GnbLog.Warnln(err)
		c.JSON(http.StatusBadRequest, model.ConsoleGnbUeHandoverResponse{
			Message: err.Error(),
		})
		return
	}

	body, err := json.Marshal(model.GnbUeHandoverRequest{Imsi: request.Imsi})
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ConsoleGnbUeHandoverResponse{
			Message: fmt.Sprintf("Failed to marshal handover request: %v", err),
		})
		return
	}

	uri := fmt.Sprintf("http://%s:%d%s", request.Ip, request.Port, constant.API_REQUEST_GNB_UE_HANDOVER)

	response, err := util.SendHttpRequest(uri, constant.API_REQUEST_GNB_UE_HANDOVER_METHOD, map[string]string{"Content-Type": constant.APPLICATION_JSON}, body)
	if err != nil {
		cs.GnbLog.Warnln(err)
		c.JSON(http.StatusInternalServerError, model.ConsoleGnbUeHandoverResponse{
			Message: err.Error(),
		})
		return
	}

	for key, values := range response.Headers {
		for _, value := range values {
			c.Header(key, value)
		}
	}

	c.Data(response.StatusCode, constant.APPLICATION_JSON, response.Body)
}
