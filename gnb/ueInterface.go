package gnb

import "net"

// implementation at RanUe and XnUe
type Ue interface {
	Identity() string
	GetUlTeid() []byte
	GetDlTeid() []byte
	GetDataPlaneAddress() *net.UDPAddr
	SetDataPlaneAddress(*net.UDPAddr)
}
