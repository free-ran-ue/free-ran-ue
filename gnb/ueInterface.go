package gnb

import "net"

// implementation at RanUe and XnUe
type Ue interface {
	GetIMSI() string
	GetUlTeid() []byte
	GetDlTeid() []byte
	GetDataPlaneAddress() *net.UDPAddr
	SetDataPlaneAddress(*net.UDPAddr)
}
