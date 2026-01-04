package util

import (
	"fmt"
	"net"
	"strconv"
)

func TcpDialWithOptionalLocalAddress(remoteAddress string, remotePort int, localAddress string) (net.Conn, error) {
	if localAddress == "" {
		return net.Dial("tcp", net.JoinHostPort(remoteAddress, strconv.Itoa(remotePort)))
	}

	// port 0 means to use any available port
	localAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(localAddress, "0"))
	if err != nil {
		return nil, fmt.Errorf("error resolving local address: %v", err)
	}

	dialer := &net.Dialer{
		LocalAddr: localAddr,
	}
	return dialer.Dial("tcp", net.JoinHostPort(remoteAddress, strconv.Itoa(remotePort)))
}
