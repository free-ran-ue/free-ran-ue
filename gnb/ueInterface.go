package gnb

import "net"

// Ue interface is implemented by RanUe and XnUe
type Ue interface {
	GetIMSI() string
	GetUlTeid() []byte
	GetDlTeid() []byte
	GetDataPlaneAddress() *net.UDPAddr
	SetDataPlaneAddress(*net.UDPAddr)
}
