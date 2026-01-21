package ue

import (
	"fmt"
	"os/exec"

	"github.com/songgao/water"
)

func bringUpUeTunnelDevice(ueTunnelDeviceName string, ip string) (*water.Interface, error) {
	tunCfg := water.Config{
		DeviceType: water.TUN,
	}
	tunCfg.Name = ueTunnelDeviceName

	tun, err := water.New(tunCfg)
	if err != nil {
		return nil, fmt.Errorf("error creating tunnel device: %v", err)
	}

	cmds := [][]string{
		{"ip", "addr", "add", fmt.Sprintf("%s/32", ip), "dev", ueTunnelDeviceName},
		{"ip", "link", "set", "dev", ueTunnelDeviceName, "up"},
	}

	for _, cmd := range cmds {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			return nil, fmt.Errorf("error bringing up tunnel device: %v", err)
		}
	}

	return tun, nil
}

func bringDownUeTunnelDevice(ueTunnelDeviceName string) error {
	cmds := [][]string{
		{"ip", "link", "set", "dev", ueTunnelDeviceName, "down"},
		{"ip", "addr", "flush", "dev", ueTunnelDeviceName},
		{"ip", "link", "delete", "dev", ueTunnelDeviceName},
	}

	for _, cmd := range cmds {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			return fmt.Errorf("error bringing down tunnel device: %v", err)
		}
	}

	return nil
}
