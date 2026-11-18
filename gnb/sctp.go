package gnb

import (
	"fmt"
	"net"

	"github.com/free5gc/sctp"
)

func getAmfAndGnbSctpN2Addr(amfN2Ips, gnbN2Ips []string, amfN2Port, gnbN2Port int) (*sctp.SCTPAddr, *sctp.SCTPAddr, error) {
	amfIps := make([]net.IPAddr, 0)
	gnbIps := make([]net.IPAddr, 0)

	for i, address := range amfN2Ips {
		ip, err := net.ResolveIPAddr("ip", address)
		if err != nil {
			return nil, nil, fmt.Errorf("error resolving AMF N2 IP item %d (%q): %w", i+1, address, err)
		}
		amfIps = append(amfIps, *ip)
	}

	amfAddr := &sctp.SCTPAddr{
		IPAddrs: amfIps,
		Port:    amfN2Port,
	}

	for i, address := range gnbN2Ips {
		ip, err := net.ResolveIPAddr("ip", address)
		if err != nil {
			return nil, nil, fmt.Errorf("error resolving GNB N2 IP item %d (%q): %w", i+1, address, err)
		}
		gnbIps = append(gnbIps, *ip)
	}

	gnbAddr := &sctp.SCTPAddr{
		IPAddrs: gnbIps,
		Port:    gnbN2Port,
	}

	return amfAddr, gnbAddr, nil
}
