package gnb

import (
	"testing"
)

var testGetMobileIdentityIMSICases = []struct {
	name     string
	buffer   []byte
	expected string
}{
	{
		name:     "3-digit-mnc-939",
		buffer:   []byte{0x01, 0x02, 0x98, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf1},
		expected: "imsi-208939000000001",
	},
	{
		name:     "2-digit-mnc-93",
		buffer:   []byte{0x01, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
		expected: "imsi-208930000000001",
	},
}

func TestGetMobileIdentityIMSI(t *testing.T) {
	for _, tc := range testGetMobileIdentityIMSICases {
		t.Run(tc.name, func(t *testing.T) {
			r := &RanUe{}
			r.mobileIdentity5GS.Buffer = tc.buffer

			if got := r.GetMobileIdentityIMSI(); got != tc.expected {
				t.Fatalf("unexpected IMSI: got %s, want %s", got, tc.expected)
			}
		})
	}
}
