package gnb

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	consoleModel "github.com/free-ran-ue/free-ran-ue/v2/console/model"
	"github.com/free-ran-ue/free-ran-ue/v2/constant"
	"github.com/free-ran-ue/free-ran-ue/v2/model"
	nasIe "github.com/free5gc/nas/ie"
	"github.com/free5gc/ngap/ie"
	"github.com/free5gc/ngap/message"
	"github.com/gin-gonic/gin"
)

var errHandoverConflict = errors.New("handover conflict")

type xnHandoverContext struct {
	MobileIdentity5GS string `json:"mobileIdentity5GS"`
}

type xnHandoverRequestContext struct {
	amfUeNgapId            int64
	ueSecurityCapabilities *ie.UESecurityCapabilities
	ulTeid                 []byte
	container              xnHandoverContext
}

func parseXnHandoverRequest(msg *message.HandoverRequest) (*xnHandoverRequestContext, error) {
	if msg.AMFUENGAPID == nil || msg.PDUSessionResourceSetupListHOReq == nil || msg.SourceToTargetTransparentContainer == nil {
		return nil, fmt.Errorf("missing mandatory IE")
	}

	ctx := &xnHandoverRequestContext{
		amfUeNgapId:            msg.AMFUENGAPID.Value,
		ueSecurityCapabilities: msg.UESecurityCapabilities,
	}

	for _, item := range msg.PDUSessionResourceSetupListHOReq.List {
		if item.PDUSessionID == nil || item.PDUSessionID.Value != constant.PDU_SESSION_ID || item.HandoverRequestTransfer == nil {
			continue
		}
		var transfer ie.PDUSessionResourceSetupRequestTransfer
		if err := ie.UnmarshalBinary(*item.HandoverRequestTransfer, &transfer); err != nil {
			return nil, fmt.Errorf("error unmarshal handover request transfer: %v", err)
		}
		if transfer.ProtocolIEs == nil {
			continue
		}
		for _, transferItem := range transfer.ProtocolIEs.List {
			if transferItem.ULNGUUPTNLInformation == nil {
				continue
			}
			if gtpTunnel, ok := transferItem.ULNGUUPTNLInformation.Choice.(*ie.GTPTunnel); ok && gtpTunnel.GTPTEID != nil {
				ctx.ulTeid = gtpTunnel.GTPTEID.Value
			}
		}
	}
	if len(ctx.ulTeid) == 0 {
		return nil, fmt.Errorf("UL TEID of pdu session %d not found", constant.PDU_SESSION_ID)
	}

	if err := json.Unmarshal(msg.SourceToTargetTransparentContainer.Value, &ctx.container); err != nil {
		return nil, fmt.Errorf("error unmarshal source to target transparent container: %v", err)
	}

	return ctx, nil
}

func parseXnHandoverRequestAcknowledge(msg *message.HandoverRequestAcknowledge) (model.HandoverCommand, error) {
	var command model.HandoverCommand
	if msg.TargetToSourceTransparentContainer == nil {
		return command, fmt.Errorf("missing target to source transparent container")
	}
	if err := json.Unmarshal(msg.TargetToSourceTransparentContainer.Value, &command); err != nil {
		return command, fmt.Errorf("error unmarshal target to source transparent container: %v", err)
	}
	if command.RanControlPlaneIp == "" || command.RanDataPlaneIp == "" || command.RanControlPlanePort == 0 || command.RanDataPlanePort == 0 {
		return command, fmt.Errorf("incomplete target addresses: %+v", command)
	}
	return command, nil
}

func xnUeContextReleaseResult(msg *message.UEContextReleaseCommand) error {
	if msg.Cause == nil {
		return fmt.Errorf("target gNB released the UE without cause")
	}
	if cause, ok := msg.Cause.Choice.(*ie.CauseRadioNetwork); ok && cause.Value == ie.CauseRadioNetworkPresentSuccessfulHandover {
		return nil
	}
	return fmt.Errorf("target gNB reported handover failure: %+v", msg.Cause.Choice)
}

func ulTeidFromPathSwitchRequestAcknowledge(msg *message.PathSwitchRequestAcknowledge, pduSessionId int64) ([]byte, error) {
	if msg.PDUSessionResourceSwitchedList == nil {
		return nil, fmt.Errorf("missing pdu session resource switched list")
	}
	for _, item := range msg.PDUSessionResourceSwitchedList.List {
		if item.PDUSessionID == nil || item.PDUSessionID.Value != pduSessionId {
			continue
		}
		if item.PathSwitchRequestAcknowledgeTransfer == nil {
			return nil, nil
		}
		var transfer ie.PathSwitchRequestAcknowledgeTransfer
		if err := ie.UnmarshalBinary(*item.PathSwitchRequestAcknowledgeTransfer, &transfer); err != nil {
			return nil, fmt.Errorf("error unmarshal path switch request acknowledge transfer: %v", err)
		}
		if transfer.ULNGUUPTNLInformation == nil {
			return nil, nil
		}
		if gtpTunnel, ok := transfer.ULNGUUPTNLInformation.Choice.(*ie.GTPTunnel); ok && gtpTunnel.GTPTEID != nil {
			return gtpTunnel.GTPTEID.Value, nil
		}
		return nil, nil
	}
	return nil, fmt.Errorf("pdu session %d not switched", pduSessionId)
}

func (g *Gnb) findRanUeByImsi(imsi string) *RanUe {
	var ranUe *RanUe
	g.ranUeConns.Range(func(key, value any) bool {
		if value.(*RanUe).GetMobileIdentityIMSI() == imsi {
			ranUe = value.(*RanUe)
			return false
		}
		return true
	})
	return ranUe
}

func (g *Gnb) releaseUeLocally(ranUe *RanUe) {
	g.ranUeConns.CompareAndDelete(ranUe.GetRanUeId(), ranUe)
	if dlTeid := ranUe.GetDlTeid(); len(dlTeid) > 0 {
		g.dlTeidToUe.CompareAndDelete(hex.EncodeToString(dlTeid), ranUe)
	}
	if address := ranUe.GetDataPlaneAddress(); address != nil {
		g.addressToUe.CompareAndDelete(address.String(), ranUe)
	}
	if err := ranUe.Release(g.ranUeNgapIdGenerator, g.teidGenerator); err != nil {
		g.RanLog.Warnf("Error releasing RAN UE %s: %v", ranUe.GetMobileIdentityIMSI(), err)
	}
}

func (g *Gnb) handleConsoleGnbUeHandover(c *gin.Context) {
	var request consoleModel.GnbUeHandoverRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		g.ApiLog.Warnf("Error bind gnb ue handover request: %v", err)
		c.JSON(http.StatusBadRequest, consoleModel.ConsoleGnbUeHandoverResponse{
			Message: fmt.Sprintf("Error bind gnb ue handover request: %v", err),
		})
		return
	}

	if !g.xnInterface.enable {
		c.JSON(http.StatusBadRequest, consoleModel.ConsoleGnbUeHandoverResponse{
			Message: "Xn interface is not enabled on this gNB",
		})
		return
	}

	ranUe := g.findRanUeByImsi(request.Imsi)
	if ranUe == nil {
		g.ApiLog.Warnf("UE %s not found", request.Imsi)
		c.JSON(http.StatusNotFound, consoleModel.ConsoleGnbUeHandoverResponse{
			Message: fmt.Sprintf("UE %s not found", request.Imsi),
		})
		return
	}

	if g.staticNrdc || ranUe.IsNrdcActivated() {
		c.JSON(http.StatusBadRequest, consoleModel.ConsoleGnbUeHandoverResponse{
			Message: fmt.Sprintf("UE %s is in NRDC, only single connection UE can be handed over", request.Imsi),
		})
		return
	}

	if err := g.processUeHandoverOut(ranUe); err != nil {
		g.ApiLog.Errorf("Error process ue %s handover: %v", request.Imsi, err)
		status := http.StatusInternalServerError
		if errors.Is(err, errHandoverConflict) {
			status = http.StatusConflict
		}
		c.JSON(status, consoleModel.ConsoleGnbUeHandoverResponse{
			Message: fmt.Sprintf("UE %s handover failed: %v", request.Imsi, err),
		})
		return
	}

	c.JSON(http.StatusOK, consoleModel.ConsoleGnbUeHandoverResponse{
		Message: fmt.Sprintf("UE %s handover success", request.Imsi),
	})
}

func (g *Gnb) processUeHandoverOut(ranUe *RanUe) error {
	imsi := ranUe.GetMobileIdentityIMSI()
	g.XnLog.Infof("Processing UE %s Xn handover (source)", imsi)

	if !ranUe.CompareAndSetHandoverState(HandoverStateNone, HandoverStatePreparing) {
		return fmt.Errorf("%w: UE %s is in handover state %s", errHandoverConflict, imsi, ranUe.GetHandoverState())
	}

	command, err := g.prepareXnHandover(ranUe)
	if err != nil {
		ranUe.SetHandoverState(HandoverStateNone)
		return fmt.Errorf("handover preparation failed: %v", err)
	}
	g.XnLog.Infof("Target gNB accepted UE %s, target control plane %s:%d, data plane %s:%d",
		imsi, command.RanControlPlaneIp, command.RanControlPlanePort, command.RanDataPlaneIp, command.RanDataPlanePort)

	commandJson, err := json.Marshal(command)
	if err != nil {
		ranUe.SetHandoverState(HandoverStateNone)
		return fmt.Errorf("error marshal handover command: %v", err)
	}

	select {
	case <-ranUe.GetHandoverReleaseChan():
	default:
	}

	ranUe.SetHandoverState(HandoverStateHandedOut)
	g.handoverOutUes.Store(imsi, ranUe)
	defer g.handoverOutUes.CompareAndDelete(imsi, ranUe)

	n, err := ranUe.GetN1Conn().Write([]byte(constant.UE_HANDOVER_COMMAND + " " + string(commandJson)))
	if err != nil {
		ranUe.SetHandoverState(HandoverStateNone)
		return fmt.Errorf("error send handover command to UE: %v", err)
	}
	g.RanLog.Tracef("Sent %d bytes of handover command to UE", n)
	g.RanLog.Infof("Sent handover command to UE %s", imsi)

	defer g.releaseUeLocally(ranUe)

	select {
	case result := <-ranUe.GetHandoverReleaseChan():
		if result != nil {
			return result
		}
	case <-time.After(2 * constant.HANDOVER_TIMEOUT):
		return fmt.Errorf("timed out waiting for Xn UE context release from target gNB")
	}

	g.XnLog.Infof("UE %s handed over to target gNB, local context released", imsi)
	return nil
}

func (g *Gnb) prepareXnHandover(ranUe *RanUe) (model.HandoverCommand, error) {
	imsi := ranUe.GetMobileIdentityIMSI()

	mobileIdentity5GS, err := ranUe.GetMobileIdentity5GS().MarshalBinary()
	if err != nil {
		return model.HandoverCommand{}, fmt.Errorf("error marshal mobile identity 5gs: %v", err)
	}
	container, err := json.Marshal(xnHandoverContext{
		MobileIdentity5GS: hex.EncodeToString(mobileIdentity5GS),
	})
	if err != nil {
		return model.HandoverCommand{}, fmt.Errorf("error marshal xn handover context: %v", err)
	}

	ueSecurityCapabilities := ranUe.GetUeSecurityCapabilities()
	if ueSecurityCapabilities == nil {
		ueSecurityCapabilities = buildUeSecurityCapabilities(nil)
	}

	handoverRequest, err := getXnHandoverRequest(ranUe.GetAmfUeId(), constant.PDU_SESSION_ID, g.plmnId, g.snssai, ueSecurityCapabilities, ranUe.GetUlTeid(), g.upfN3Ip, container)
	if err != nil {
		return model.HandoverCommand{}, fmt.Errorf("error get xn handover request: %v", err)
	}
	g.XnLog.Tracef("Get Xn handover request: %+v", handoverRequest)

	respData, err := g.xnRoundTrip(imsi, handoverRequest)
	if err != nil {
		return model.HandoverCommand{}, err
	}
	if len(respData) == 0 {
		return model.HandoverCommand{}, fmt.Errorf("target gNB rejected the handover request")
	}

	ngapMsg, err := message.Parse(respData)
	if err != nil {
		return model.HandoverCommand{}, fmt.Errorf("error decode xn handover response: %v", err)
	}
	ack, ok := ngapMsg.(*message.HandoverRequestAcknowledge)
	if !ok {
		return model.HandoverCommand{}, fmt.Errorf("unexpected xn handover response: %T", ngapMsg)
	}
	return parseXnHandoverRequestAcknowledge(ack)
}

func xnUeContextReleaseProcessor(g *Gnb, conn net.Conn, imsi string, msg *message.UEContextReleaseCommand) {
	result := xnUeContextReleaseResult(msg)

	if value, ok := g.handoverOutUes.Load(imsi); ok {
		select {
		case value.(*RanUe).GetHandoverReleaseChan() <- result:
		default:
		}
		g.XnLog.Infof("Received Xn UE context release for UE %s, result: %v", imsi, result)
	} else {
		g.XnLog.Warnf("Received Xn UE context release for UE %s which is not handed out", imsi)
	}

	xnPduBytes, err := NewXnPdu(imsi, []byte{}).Marshal()
	if err != nil {
		g.XnLog.Warnf("Error marshal xn pdu: %v", err)
		return
	}
	if _, err := conn.Write(xnPduBytes); err != nil {
		g.XnLog.Warnf("Error write xn ue context release response: %v", err)
	}
}

func xnHandoverRequestProcessor(g *Gnb, conn net.Conn, imsi string, msg *message.HandoverRequest) {
	reply := func(data []byte) {
		xnPduBytes, err := NewXnPdu(imsi, data).Marshal()
		if err != nil {
			g.XnLog.Warnf("Error marshal xn pdu: %v", err)
			return
		}
		if _, err := conn.Write(xnPduBytes); err != nil {
			g.XnLog.Warnf("Error write xn handover response: %v", err)
		}
	}

	ranUe, err := g.admitIncomingHandover(imsi, msg)
	if err != nil {
		g.XnLog.Warnf("Reject Xn handover request of UE %s: %v", imsi, err)
		reply(nil)
		return
	}

	container, err := json.Marshal(model.HandoverCommand{
		RanControlPlaneIp:   g.ranControlPlaneIp,
		RanControlPlanePort: g.ranControlPlanePort,
		RanDataPlaneIp:      g.ranDataPlaneIp,
		RanDataPlanePort:    g.ranDataPlanePort,
	})
	if err == nil {
		var ack []byte
		ack, err = getXnHandoverRequestAcknowledge(ranUe.GetAmfUeId(), ranUe.GetRanUeId(), constant.PDU_SESSION_ID, ranUe.GetDlTeid(), g.ranN3Ip, 1, container)
		if err == nil {
			if _, loaded := g.pendingHandoverUes.LoadOrStore(imsi, ranUe); loaded {
				err = fmt.Errorf("UE %s already has a pending handover", imsi)
			} else {
				time.AfterFunc(constant.HANDOVER_TIMEOUT, func() {
					if g.pendingHandoverUes.CompareAndDelete(imsi, ranUe) {
						g.XnLog.Warnf("UE %s did not arrive within %v, drop pending handover", imsi, constant.HANDOVER_TIMEOUT)
						g.releaseUeLocally(ranUe)
					}
				})
				g.XnLog.Infof("Accepted Xn handover request of UE %s, RAN UE NGAP ID %d, DL TEID %s",
					imsi, ranUe.GetRanUeId(), hex.EncodeToString(ranUe.GetDlTeid()))
				reply(ack)
				return
			}
		}
	}

	g.XnLog.Warnf("Reject Xn handover request of UE %s: %v", imsi, err)
	g.releaseUeLocally(ranUe)
	reply(nil)
}

func (g *Gnb) admitIncomingHandover(imsi string, msg *message.HandoverRequest) (*RanUe, error) {
	ctx, err := parseXnHandoverRequest(msg)
	if err != nil {
		return nil, err
	}
	if g.findRanUeByImsi(imsi) != nil {
		return nil, fmt.Errorf("UE %s is already served by this gNB", imsi)
	}
	if _, exists := g.pendingHandoverUes.Load(imsi); exists {
		return nil, fmt.Errorf("UE %s already has a pending handover", imsi)
	}

	mobileIdentity5GSBytes, err := hex.DecodeString(ctx.container.MobileIdentity5GS)
	if err != nil {
		return nil, fmt.Errorf("error decode mobile identity 5gs: %v", err)
	}
	mobileIdentity5GS := new(nasIe.MobileId5GS)
	if err := mobileIdentity5GS.UnmarshalBinary(mobileIdentity5GSBytes); err != nil {
		return nil, fmt.Errorf("error unmarshal mobile identity 5gs: %v", err)
	}

	ranUe, err := NewRanUe(nil, g.ranUeNgapIdGenerator)
	if err != nil {
		return nil, err
	}
	ranUe.SetAmfUeId(ctx.amfUeNgapId)
	ranUe.SetMobileIdentity5GS(mobileIdentity5GS)
	ranUe.SetUeSecurityCapabilities(ctx.ueSecurityCapabilities)
	ranUe.SetUlTeid(ctx.ulTeid)
	ranUe.SetHandoverState(HandoverStateIncoming)

	if ranUe.GetMobileIdentityIMSI() != imsi {
		g.releaseUeLocally(ranUe)
		return nil, fmt.Errorf("mobile identity %s does not match xn imsi %s", ranUe.GetMobileIdentityIMSI(), imsi)
	}

	dlTeid, err := g.teidGenerator.AllocateTeid()
	if err != nil {
		g.releaseUeLocally(ranUe)
		return nil, fmt.Errorf("error allocate dl teid: %v", err)
	}
	ranUe.SetDlTeid(dlTeid)

	return ranUe, nil
}

func (g *Gnb) handleHandoverInConnection(ctx context.Context, conn net.Conn, imsi string) {
	value, ok := g.pendingHandoverUes.LoadAndDelete(imsi)
	if !ok {
		g.RanLog.Warnf("No pending handover for UE %s from %v, close connection", imsi, conn.RemoteAddr())
		if err := conn.Close(); err != nil {
			g.RanLog.Errorf("Error closing UE connection: %v", err)
		}
		return
	}
	ranUe := value.(*RanUe)
	ranUe.SetN1Conn(conn)
	g.ranUeConns.Store(ranUe.GetRanUeId(), ranUe)
	g.RanLog.Infof("UE %s arrived by handover from %v", imsi, conn.RemoteAddr())

	defer g.closeRanConnection(ranUe)

	if err := g.processUeHandoverIn(ranUe); err != nil {
		g.XnLog.Errorf("Error process UE %s handover (target): %v", imsi, err)
		return
	}

	g.waitUeRelease(ctx, ranUe)
}

func (g *Gnb) processUeHandoverIn(ranUe *RanUe) error {
	imsi := ranUe.GetMobileIdentityIMSI()
	g.NgapLog.Infof("Processing UE %s path switch", imsi)

	g.dlTeidToUe.Store(hex.EncodeToString(ranUe.GetDlTeid()), ranUe)
	g.imsiTodlTeidAndUeType.Store(imsi, dlTeidAndUeType{
		dlTeid: ranUe.GetDlTeid(),
		ueType: constant.UE_TYPE_RAN,
	})
	g.markImsiReady(imsi)

	result := g.processPathSwitch(ranUe)

	cause := ie.CauseRadioNetworkPresentSuccessfulHandover
	if result != nil {
		cause = ie.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem
	}
	release, err := getXnUeContextRelease(ranUe.GetAmfUeId(), ranUe.GetRanUeId(), cause)
	if err != nil {
		g.XnLog.Warnf("Error get xn ue context release: %v", err)
	} else if _, err := g.xnRoundTrip(imsi, release); err != nil {
		g.XnLog.Warnf("Error send xn ue context release to source gNB: %v", err)
	} else {
		g.XnLog.Debugf("Sent Xn UE context release of UE %s to source gNB", imsi)
	}

	if result != nil {
		return fmt.Errorf("path switch failed: %v", result)
	}

	ranUe.SetHandoverState(HandoverStateNone)
	g.NgapLog.Infof("UE %s path switch completed, handover finished", imsi)
	return nil
}

func (g *Gnb) processPathSwitch(ranUe *RanUe) error {
	pathSwitchRequestTransfer, err := getPathSwitchRequestTransfer(ranUe.GetDlTeid(), g.ranN3Ip, 1)
	if err != nil {
		return err
	}

	ueSecurityCapabilities := ranUe.GetUeSecurityCapabilities()
	if ueSecurityCapabilities == nil {
		ueSecurityCapabilities = buildUeSecurityCapabilities(nil)
	}

	pathSwitchRequest, err := getPathSwitchRequest(ranUe.GetRanUeId(), ranUe.GetAmfUeId(), constant.PDU_SESSION_ID, g.plmnId, g.tai, g.gnbId, ueSecurityCapabilities, pathSwitchRequestTransfer)
	if err != nil {
		return fmt.Errorf("error get path switch request: %v", err)
	}
	g.NgapLog.Tracef("Get path switch request: %+v", pathSwitchRequest)

	n, err := g.n2Conn.Write(pathSwitchRequest)
	if err != nil {
		return fmt.Errorf("error send path switch request to AMF: %v", err)
	}
	g.NgapLog.Tracef("Sent %d bytes of path switch request to AMF", n)
	g.NgapLog.Debugln("Sent path switch request to AMF")

	select {
	case result := <-ranUe.GetPathSwitchResultChan():
		return result
	case <-time.After(constant.HANDOVER_TIMEOUT):
		return fmt.Errorf("timed out waiting for path switch request acknowledge")
	}
}
