package gnb

import (
	"testing"

	"github.com/go-playground/assert"
)

var testGetAmfAndGnbSctpN2AddrCases = []struct {
	name      string
	amfN2Ips  []string
	gnbN2Ips  []string
	amfN2Port int
	gnbN2Port int
}{
	{
		name:      "testGetAmfAndGnbSctpN2Addr",
		amfN2Ips:  []string{"127.0.0.18", "127.0.0.19"},
		gnbN2Ips:  []string{"127.0.0.1", "127.0.0.2"},
		amfN2Port: 38412,
		gnbN2Port: 38413,
	},
}

func TestGetAmfAndGnbSctpN2Addr(t *testing.T) {
	for _, testCase := range testGetAmfAndGnbSctpN2AddrCases {
		t.Run(testCase.name, func(t *testing.T) {
			amfAddr, gnbAddr, err := getAmfAndGnbSctpN2Addr(testCase.amfN2Ips, testCase.gnbN2Ips, testCase.amfN2Port, testCase.gnbN2Port)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if amfAddr == nil || gnbAddr == nil {
				t.Fatal("expected non-nil AMF and GNB addresses")
			}

			if len(amfAddr.IPAddrs) != len(testCase.amfN2Ips) {
				t.Fatalf(
					"AMF address count: got %d, want %d",
					len(amfAddr.IPAddrs),
					len(testCase.amfN2Ips),
				)
			}

			if len(gnbAddr.IPAddrs) != len(testCase.gnbN2Ips) {
				t.Fatalf(
					"GNB address count: got %d, want %d",
					len(gnbAddr.IPAddrs),
					len(testCase.gnbN2Ips),
				)
			}

			for i, expectedIP := range testCase.amfN2Ips {
				assert.Equal(t, expectedIP, amfAddr.IPAddrs[i].String())
			}
			for i, expectedIP := range testCase.gnbN2Ips {
				assert.Equal(t, expectedIP, gnbAddr.IPAddrs[i].String())
			}

			assert.Equal(t, testCase.amfN2Port, amfAddr.Port)
			assert.Equal(t, testCase.gnbN2Port, gnbAddr.Port)
		})
	}
}
