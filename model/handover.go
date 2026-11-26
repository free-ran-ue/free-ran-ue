package model

type HandoverCommand struct {
	RanControlPlaneIp   string `json:"ranControlPlaneIp"`
	RanControlPlanePort int    `json:"ranControlPlanePort"`
	RanDataPlaneIp      string `json:"ranDataPlaneIp"`
	RanDataPlanePort    int    `json:"ranDataPlanePort"`
}
