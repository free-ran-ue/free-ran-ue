package model

type ConsoleGnbInfoRequest struct {
	Ip   string `json:"ip"`
	Port int    `json:"port"`
}

type ConsoleGnbInfoResponse struct {
	Message string  `json:"message"`
	GnbInfo GnbInfo `json:"gnbInfo"`
}

type GnbInfo struct {
	GnbId   string `json:"gnbId"`
	GnbName string `json:"gnbName"`

	PlmnId string `json:"plmnId"`

	Snssai SnssaiIE `json:"snssai"`

	RanUeList []RanUeInfo `json:"ranUeList"`
	XnUeList  []XnUeInfo  `json:"xnUeList"`

	XnInterface XnInterfaceInfo `json:"xnInterface"`
}

type XnInterfaceInfo struct {
	Enable     bool   `json:"enable"`
	ListenIp   string `json:"listenIp"`
	ListenPort int    `json:"listenPort"`
	DialIp     string `json:"dialIp"`
	DialPort   int    `json:"dialPort"`
}

type SnssaiIE struct {
	Sst string `json:"sst"`
	Sd  string `json:"sd"`
}

type RanUeInfo struct {
	Imsi          string `json:"imsi"`
	NrdcIndicator bool   `json:"nrdcIndicator"`
}

type XnUeInfo struct {
	Imsi string `json:"imsi"`
}

type ConsoleGnbUeNrdcModifyRequest struct {
	Ip   string `json:"ip"`
	Port int    `json:"port"`
	Imsi string `json:"imsi"`
}

type ConsoleGnbUeNrdcModifyResponse struct {
	Message string `json:"message"`
}

type ConsoleGnbUeHandoverRequest struct {
	Ip   string `json:"ip"`
	Port int    `json:"port"`
	Imsi string `json:"imsi"`

	TargetIp   string `json:"targetIp"`
	TargetPort int    `json:"targetPort"`
}

type ConsoleGnbUeHandoverResponse struct {
	Message string `json:"message"`
}

type GnbUeHandoverRequest struct {
	Imsi string `json:"imsi"`
}
