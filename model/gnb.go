package model

type GnbConfig struct {
	Gnb    GnbIE    `yaml:"gnb" valid:"required"`
	Logger LoggerIE `yaml:"logger" valid:"required"`
}

type GnbIE struct {
	AmfN2Ip N2IPList `yaml:"amfN2Ip" valid:"required"`
	RanN2Ip N2IPList `yaml:"ranN2Ip" valid:"required"`
	UpfN3Ip string   `yaml:"upfN3Ip" valid:"required"`
	RanN3Ip string   `yaml:"ranN3Ip" valid:"required"`

	RanControlPlaneIp string `yaml:"ranControlPlaneIp" valid:"required"`
	RanDataPlaneIp    string `yaml:"ranDataPlaneIp" valid:"required"`

	AmfN2Port int `yaml:"amfN2Port" valid:"required"`
	RanN2Port int `yaml:"ranN2Port" valid:"required"`
	UpfN3Port int `yaml:"upfN3Port" valid:"required"`
	RanN3Port int `yaml:"ranN3Port" valid:"required"`

	RanControlPlanePort int `yaml:"ranControlPlanePort" valid:"required"`
	RanDataPlanePort    int `yaml:"ranDataPlanePort" valid:"required"`

	GnbId   string `yaml:"gnbId" valid:"required"`
	GnbName string `yaml:"gnbName" valid:"required"`

	PlmnId PlmnIdIE `yaml:"plmnId" valid:"required"`

	Tai    TaiIE    `yaml:"tai" valid:"required"`
	Snssai SnssaiIE `yaml:"snssai" valid:"required"`

	StaticNrdc bool `yaml:"staticNrdc"`

	XnInterface XnInterfaceIE `yaml:"xnInterface"`

	Api ApiIE `yaml:"api" valid:"required"`
}

type XnInterfaceIE struct {
	Enable bool `yaml:"enable" valid:"required"`

	XnListenIp   string `yaml:"xnListenIp" valid:"required"`
	XnListenPort int    `yaml:"xnListenPort" valid:"required"`

	XnDialIp   string `yaml:"xnDialIp" valid:"required"`
	XnDialPort int    `yaml:"xnDialPort" valid:"required"`
}

type ApiIE struct {
	Ip   string `yaml:"ip" valid:"required"`
	Port int    `yaml:"port" valid:"required"`
}
