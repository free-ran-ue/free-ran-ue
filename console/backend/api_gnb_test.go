package backend

import (
	"testing"

	"github.com/free-ran-ue/free-ran-ue/v2/console/model"
	"github.com/stretchr/testify/assert"
)

func TestValidateHandoverTarget(t *testing.T) {
	master := &model.GnbInfo{
		GnbId: "000314", GnbName: "gNB-master",
		XnInterface: model.XnInterfaceInfo{Enable: true, ListenIp: "10.0.1.2", ListenPort: 31415, DialIp: "10.0.1.3", DialPort: 31415},
	}
	secondary := &model.GnbInfo{
		GnbId: "314314", GnbName: "gNB-secondary",
		XnInterface: model.XnInterfaceInfo{Enable: true, ListenIp: "10.0.1.3", ListenPort: 31415, DialIp: "10.0.1.2", DialPort: 31415},
	}
	other := &model.GnbInfo{
		GnbId: "777777", GnbName: "gNB-other",
		XnInterface: model.XnInterfaceInfo{Enable: true, ListenIp: "10.0.1.4", ListenPort: 31415, DialIp: "10.0.1.2", DialPort: 31415},
	}
	xnDisabled := &model.GnbInfo{GnbId: "888888", GnbName: "gNB-no-xn"}

	assert.NoError(t, validateHandoverTarget(master, secondary))
	assert.NoError(t, validateHandoverTarget(secondary, master))
	assert.Error(t, validateHandoverTarget(master, master))
	assert.Error(t, validateHandoverTarget(master, other))
	assert.Error(t, validateHandoverTarget(master, xnDisabled))
	assert.Error(t, validateHandoverTarget(xnDisabled, master))
}
