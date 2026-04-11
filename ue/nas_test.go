package ue

import (
	"testing"

	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/openapi/models"
	"github.com/go-playground/assert"
)

var testBuildUeMobileIdentity5GSCases = []struct {
	name     string
	mccLength int
	mncLength int
	supi     string
	expected nasType.MobileIdentity5GS
}{
	{
		name: "imsi-2089300007487",
		mccLength: 3,
		mncLength: 2,
		supi: "2089300007487",
		expected: nasType.MobileIdentity5GS{
			Len:    12,
			Buffer: []byte{0x01, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
		},
	},
	{
		name: "imsi-208930000000001",
		mccLength: 3,
		mncLength: 2,
		supi: "208930000000001",
		expected: nasType.MobileIdentity5GS{
			Len:    13,
			Buffer: []byte{0x01, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
		},
	},
	{
		name:           "imsi-001001000000001",
		mccLength:      3,
		mncLength:      3,
		supi:           "001001000000001",
		expected: nasType.MobileIdentity5GS{
			Len:    13,
			Buffer: []byte{0x01, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1},
		},
	},
	{
		name:           "imsi-208939000000001",
		mccLength:      3,
		mncLength:      3,
		supi:           "208939000000001",
		expected: nasType.MobileIdentity5GS{
			Len:    13,
			Buffer: []byte{0x01, 0x02, 0x98, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1},
		},
	},
}

func TestBuildUeMobileIdentity5GS(t *testing.T) {
	for _, testCase := range testBuildUeMobileIdentity5GSCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := buildUeMobileIdentity5GS(testCase.mccLength, testCase.mncLength, testCase.supi)
			assert.Equal(t, testCase.expected.Len, result.Len)
			assert.Equal(t, testCase.expected.Buffer, result.Buffer)
		})
	}
}

var testBuildUeRegistrationRequestCases = []struct {
	name              string
	mobileIdentity5GS nasType.MobileIdentity5GS
	expectedError     error
	expected          []byte
}{
	{
		name: "imsi-208930000007487",
		mobileIdentity5GS: nasType.MobileIdentity5GS{
			Len:    12,
			Buffer: []byte{0x01, 0x02, 0xf8, 0x39, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
		},
		expectedError: nil,
		expected:      []byte{0x7e, 0x00, 0x41, 0x79, 0x00, 0x0c, 0x01, 0x02, 0xf8, 0x39, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	},
}

func TestBuildUeRegistrationRequest(t *testing.T) {
	for _, testCase := range testBuildUeRegistrationRequestCases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := buildUeRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration, &testCase.mobileIdentity5GS, nil, nil, nil, nil, nil)
			assert.Equal(t, testCase.expectedError, err)
			assert.Equal(t, testCase.expected, result)
		})
	}
}

var testBuildAuthenticationResponseCases = []struct {
	name          string
	param         []byte
	expectedError error
}{
	{
		name:          "testBuildAuthenticationResponse",
		param:         []byte{0x7e, 0x00, 0x41, 0x79, 0x00, 0x0c, 0x01, 0x02, 0xf8, 0x39, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
		expectedError: nil,
	},
}

func TestBuildAuthenticationResponse(t *testing.T) {
	for _, testCase := range testBuildAuthenticationResponseCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := buildAuthenticationResponse(testCase.param)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}

var testBuildNasSecurityModeCompleteMessageCases = []struct {
	name          string
	param         []byte
	expectedError error
}{
	{
		name:          "testBuildNasSecurityModeCompleteMessage",
		param:         []byte{0x7e, 0x00, 0x41, 0x79, 0x00, 0x0c, 0x01, 0x02, 0xf8, 0x39, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
		expectedError: nil,
	},
}

func TestBuildNasSecurityModeCompleteMessage(t *testing.T) {
	for _, testCase := range testBuildNasSecurityModeCompleteMessageCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := buildNasSecurityModeCompleteMessage(testCase.param)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}

var testBuildNasRegistrationCompleteMessageCases = []struct {
	name          string
	param         []byte
	expectedError error
}{
	{
		name:          "testBuildNasRegistrationCompleteMessage",
		param:         []byte{0x7e, 0x00, 0x41, 0x79, 0x00, 0x0c, 0x01, 0x02, 0xf8, 0x39, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
		expectedError: nil,
	},
}

func TestBuildNasRegistrationCompleteMessage(t *testing.T) {
	for _, testCase := range testBuildNasRegistrationCompleteMessageCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := buildNasRegistrationCompleteMessage(testCase.param)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}

var testBuildPduSessionEstablishmentRequestCases = []struct {
	name          string
	pduSessionId  uint8
	expectedError error
}{
	{
		name:          "testBuildPduSessionEstablishmentRequest",
		pduSessionId:  4,
		expectedError: nil,
	},
}

func TestBuildPduSessionEstablishmentRequest(t *testing.T) {
	for _, testCase := range testBuildPduSessionEstablishmentRequestCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := buildPduSessionEstablishmentRequest(testCase.pduSessionId)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}

var testBuildUlNasTransportMessageCases = []struct {
	name                string
	nasMessageContainer []byte
	pduSessionId        uint8
	requestType         uint8
	dnn                 string
	sNssai              *models.Snssai
	expectedError       error
}{
	{
		name:                "testBuildUlNasTransportMessage",
		nasMessageContainer: []byte{0x7e, 0x00, 0x41, 0x79, 0x00, 0x0c, 0x01, 0x02, 0xf8, 0x39, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
		pduSessionId:        4,
		requestType:         0,
		dnn:                 "internet",
		sNssai: &models.Snssai{
			Sst: 1,
			Sd:  "010203",
		},
		expectedError: nil,
	},
}

func TestBuildUlNasTransportMessage(t *testing.T) {
	for _, testCase := range testBuildUlNasTransportMessageCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := buildUlNasTransportMessage(testCase.nasMessageContainer, testCase.pduSessionId, testCase.requestType, testCase.dnn, testCase.sNssai)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}

var testBuildUeDeRegistrationRequestCases = []struct {
	name              string
	accessType        uint8
	switchOff         uint8
	ngKsi             uint8
	mobileIdentity5GS nasType.MobileIdentity5GS
	expectedError     error
}{
	{
		name:       "imsi-208930000007487",
		accessType: nasMessage.AccessType3GPP,
		switchOff:  0x00,
		ngKsi:      0x04,
		mobileIdentity5GS: nasType.MobileIdentity5GS{
			Len:    12,
			Buffer: []byte{0x01, 0x02, 0xf8, 0x39, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
		},
		expectedError: nil,
	},
}

func TestBuildUeDeRegistrationRequest(t *testing.T) {
	for _, testCase := range testBuildUeDeRegistrationRequestCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := buildUeDeRegistrationRequest(testCase.accessType, testCase.switchOff, testCase.ngKsi, testCase.mobileIdentity5GS)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
