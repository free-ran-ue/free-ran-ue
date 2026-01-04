package util

import (
	"fmt"
	"net"
	"strconv"
)

func UdpDialWithOptionalLocalAddress(remoteAddress string, remotePort int, localAddress string) (net.Conn, error) {
	if localAddress == "" {
		return net.Dial("udp", net.JoinHostPort(remoteAddress, strconv.Itoa(remotePort)))
	}

	localAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(localAddress, "0"))
	if err != nil {
		return nil, fmt.Errorf("error resolving local address: %v", err)
	}

	dialer := &net.Dialer{
		LocalAddr: localAddr,
	}
	return dialer.Dial("udp", net.JoinHostPort(remoteAddress, strconv.Itoa(remotePort)))
}
