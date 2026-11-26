package gnb

import (
	"encoding/json"
	"testing"

	"github.com/free-ran-ue/free-ran-ue/v2/model"
	nasIe "github.com/free5gc/nas/ie"
	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	"github.com/free5gc/ngap/message"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testHandoverPlmnId = ie.PLMNIdentity{Value: aper.OctetString("\x02\xF8\x39")}
	testHandoverTai    = ie.TAI{
		TAC:          &ie.TAC{Value: aper.OctetString("\x00\x00\x01")},
		PLMNIdentity: &ie.PLMNIdentity{Value: aper.OctetString("\x02\xF8\x39")},
	}
	testHandoverSnssai = ie.SNSSAI{
		SST: &ie.SST{Value: aper.OctetString("\x01")},
		SD:  &ie.SD{Value: aper.OctetString("\x01\x02\x03")},
	}
)

func gtpTunnelOf(t *testing.T, info *ie.UPTransportLayerInformation) *ie.GTPTunnel {
	t.Helper()
	require.NotNil(t, info)
	gtpTunnel, ok := info.Choice.(*ie.GTPTunnel)
	require.True(t, ok)
	require.NotNil(t, gtpTunnel.GTPTEID)
	return gtpTunnel
}

func TestBuildUeSecurityCapabilities(t *testing.T) {
	testCases := []struct {
		name          string
		nasCapability *nasIe.UESecCapability
		expectedEA    byte
		expectedIA    byte
	}{
		{
			name:          "nil capability",
			nasCapability: nil,
		},
		{
			name:          "nea0 + nia2",
			nasCapability: &nasIe.UESecCapability{EA05G: true, IA2_128_5G: true},
			expectedEA:    0x00,
			expectedIA:    0x40,
		},
		{
			name: "all 128-bit algorithms",
			nasCapability: &nasIe.UESecCapability{
				EA1_128_5G: true, EA2_128_5G: true, EA3_128_5G: true,
				IA1_128_5G: true, IA2_128_5G: true, IA3_128_5G: true,
			},
			expectedEA: 0xe0,
			expectedIA: 0xe0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			capabilities := buildUeSecurityCapabilities(tc.nasCapability)
			assert.Equal(t, tc.expectedEA, capabilities.NRencryptionAlgorithms.Value.Bytes[0])
			assert.Equal(t, tc.expectedIA, capabilities.NRintegrityProtectionAlgorithms.Value.Bytes[0])
			assert.Equal(t, uint64(16), capabilities.NRencryptionAlgorithms.Value.BitLength)
		})
	}
}

func TestXnHandoverRequestRoundTrip(t *testing.T) {
	ulTeid := []byte{0x00, 0x00, 0x00, 0x07}
	container, err := json.Marshal(xnHandoverContext{MobileIdentity5GS: "0102f839"})
	require.NoError(t, err)

	encoded, err := getXnHandoverRequest(5, 4, testHandoverPlmnId, testHandoverSnssai, buildUeSecurityCapabilities(&nasIe.UESecCapability{IA2_128_5G: true}), ulTeid, "10.0.1.1", container)
	require.NoError(t, err)

	decoded, err := message.Parse(encoded)
	require.NoError(t, err)
	handoverRequest, ok := decoded.(*message.HandoverRequest)
	require.True(t, ok)

	ctx, err := parseXnHandoverRequest(handoverRequest)
	require.NoError(t, err)
	assert.Equal(t, int64(5), ctx.amfUeNgapId)
	assert.Equal(t, ulTeid, ctx.ulTeid)
	assert.Equal(t, "0102f839", ctx.container.MobileIdentity5GS)
	assert.Equal(t, byte(0x40), ctx.ueSecurityCapabilities.NRintegrityProtectionAlgorithms.Value.Bytes[0])
}

func TestXnHandoverRequestAcknowledgeRoundTrip(t *testing.T) {
	command := model.HandoverCommand{
		RanControlPlaneIp:   "10.0.3.1",
		RanControlPlanePort: 31413,
		RanDataPlaneIp:      "10.0.3.1",
		RanDataPlanePort:    31414,
	}
	container, err := json.Marshal(command)
	require.NoError(t, err)

	encoded, err := getXnHandoverRequestAcknowledge(5, 2, 4, []byte{0x00, 0x00, 0x00, 0x03}, "10.0.1.3", 1, container)
	require.NoError(t, err)

	decoded, err := message.Parse(encoded)
	require.NoError(t, err)
	ack, ok := decoded.(*message.HandoverRequestAcknowledge)
	require.True(t, ok)

	got, err := parseXnHandoverRequestAcknowledge(ack)
	require.NoError(t, err)
	assert.Equal(t, command, got)
}

func TestPathSwitchRequestRoundTrip(t *testing.T) {
	dlTeid := []byte{0x00, 0x00, 0x00, 0x03}
	transfer, err := getPathSwitchRequestTransfer(dlTeid, "10.0.1.3", 1)
	require.NoError(t, err)

	encoded, err := getPathSwitchRequest(2, 5, 4, testHandoverPlmnId, testHandoverTai, []byte("\x31\x43\x14"), buildUeSecurityCapabilities(nil), transfer)
	require.NoError(t, err)

	decoded, err := message.Parse(encoded)
	require.NoError(t, err)
	pathSwitchRequest, ok := decoded.(*message.PathSwitchRequest)
	require.True(t, ok)

	assert.Equal(t, int64(2), pathSwitchRequest.RANUENGAPID.Value)
	assert.Equal(t, int64(5), pathSwitchRequest.SourceAMFUENGAPID.Value)
	require.NotNil(t, pathSwitchRequest.UserLocationInformation)
	require.Len(t, pathSwitchRequest.PDUSessionResourceToBeSwitchedDLList.List, 1)

	item := pathSwitchRequest.PDUSessionResourceToBeSwitchedDLList.List[0]
	assert.Equal(t, int64(4), item.PDUSessionID.Value)

	var decodedTransfer ie.PathSwitchRequestTransfer
	require.NoError(t, ie.UnmarshalBinary(*item.PathSwitchRequestTransfer, &decodedTransfer))
	gtpTunnel := gtpTunnelOf(t, decodedTransfer.DLNGUUPTNLInformation)
	assert.Equal(t, aper.OctetString(dlTeid), gtpTunnel.GTPTEID.Value)
	assert.Equal(t, ngapConvertIPAddressToNgap("10.0.1.3"), gtpTunnel.TransportLayerAddress.Value)
	require.Len(t, decodedTransfer.QosFlowAcceptedList.List, 1)
	assert.Equal(t, int64(1), decodedTransfer.QosFlowAcceptedList.List[0].QosFlowIdentifier.Value)
}

func TestXnUeContextReleaseRoundTrip(t *testing.T) {
	encoded, err := getXnUeContextRelease(5, 2, ie.CauseRadioNetworkPresentSuccessfulHandover)
	require.NoError(t, err)

	decoded, err := message.Parse(encoded)
	require.NoError(t, err)
	release, ok := decoded.(*message.UEContextReleaseCommand)
	require.True(t, ok)

	assert.NoError(t, xnUeContextReleaseResult(release))

	encoded, err = getXnUeContextRelease(5, 2, ie.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem)
	require.NoError(t, err)
	decoded, err = message.Parse(encoded)
	require.NoError(t, err)
	assert.Error(t, xnUeContextReleaseResult(decoded.(*message.UEContextReleaseCommand)))
}

func TestUlTeidFromPathSwitchRequestAcknowledge(t *testing.T) {
	ulTeid := []byte{0x00, 0x00, 0x00, 0x09}
	transferMessage := ie.PathSwitchRequestAcknowledgeTransfer{
		ULNGUUPTNLInformation: buildGtpTunnel(ulTeid, "10.0.1.1"),
	}
	encodedTransfer, err := ie.MarshalBinary(&transferMessage)
	require.NoError(t, err)
	transfer := aper.OctetString(encodedTransfer)

	ack := &message.PathSwitchRequestAcknowledge{
		PDUSessionResourceSwitchedList: &ie.PDUSessionResourceSwitchedList{
			List: []ie.PDUSessionResourceSwitchedItem{
				{
					PDUSessionID:                         &ie.PDUSessionID{Value: 4},
					PathSwitchRequestAcknowledgeTransfer: &transfer,
				},
			},
		},
	}

	got, err := ulTeidFromPathSwitchRequestAcknowledge(ack, 4)
	require.NoError(t, err)
	assert.Equal(t, ulTeid, got)

	_, err = ulTeidFromPathSwitchRequestAcknowledge(ack, 5)
	assert.Error(t, err)
}

func TestMobileIdentity5GSSurvivesXnTransfer(t *testing.T) {
	for _, tc := range testGetMobileIdentityIMSICases {
		t.Run(tc.name, func(t *testing.T) {
			source := new(nasIe.MobileId5GS)
			require.NoError(t, source.UnmarshalBinary(tc.buffer))

			encoded, err := source.MarshalBinary()
			require.NoError(t, err)

			target := new(nasIe.MobileId5GS)
			require.NoError(t, target.UnmarshalBinary(encoded))

			r := &RanUe{mobileIdentity5GS: target}
			assert.Equal(t, tc.expected, r.GetMobileIdentityIMSI())
		})
	}
}

func TestRanUeReleaseIsIdempotent(t *testing.T) {
	idGenerator := NewRanUeNgapIdGenerator()
	teidGenerator := NewTeidGenerator()

	ranUe, err := NewRanUe(nil, idGenerator)
	require.NoError(t, err)
	dlTeid, err := teidGenerator.AllocateTeid()
	require.NoError(t, err)
	ranUe.SetDlTeid(dlTeid)

	assert.NoError(t, ranUe.Release(idGenerator, teidGenerator))
	assert.NoError(t, ranUe.Release(idGenerator, teidGenerator))
}

func TestRanUeHandoverStateTransition(t *testing.T) {
	ranUe, err := NewRanUe(nil, NewRanUeNgapIdGenerator())
	require.NoError(t, err)

	assert.True(t, ranUe.CompareAndSetHandoverState(HandoverStateNone, HandoverStatePreparing))
	assert.False(t, ranUe.CompareAndSetHandoverState(HandoverStateNone, HandoverStatePreparing))
	assert.Equal(t, HandoverStatePreparing, ranUe.GetHandoverState())
}
