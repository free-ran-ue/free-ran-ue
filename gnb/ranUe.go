package gnb

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/free-ran-ue/free-ran-ue/v2/constant"
	"github.com/free5gc/nas/ie"
	ngapIe "github.com/free5gc/ngap/ie"
)

type RanUeNgapIdGenerator struct {
	usedRanUeIds sync.Map
	mtx          sync.Mutex
}

func NewRanUeNgapIdGenerator() *RanUeNgapIdGenerator {
	return &RanUeNgapIdGenerator{
		usedRanUeIds: sync.Map{},
		mtx:          sync.Mutex{},
	}
}

func (g *RanUeNgapIdGenerator) AllocateRanUeId() (int64, error) {
	g.mtx.Lock()
	defer g.mtx.Unlock()

	for i := 1; i <= 65535; i++ {
		if _, exists := g.usedRanUeIds.Load(int64(i)); !exists {
			g.usedRanUeIds.Store(int64(i), true)
			return int64(i), nil
		}
	}

	return 0, fmt.Errorf("ranUeId pool exhausted")
}

func (g *RanUeNgapIdGenerator) ReleaseRanUeId(ranUeId int64) {
	g.mtx.Lock()
	defer g.mtx.Unlock()

	g.usedRanUeIds.Delete(ranUeId)
}

type HandoverState int

const (
	HandoverStateNone HandoverState = iota
	HandoverStatePreparing
	HandoverStateHandedOut
	HandoverStateIncoming
)

func (s HandoverState) String() string {
	switch s {
	case HandoverStateNone:
		return "none"
	case HandoverStatePreparing:
		return "preparing"
	case HandoverStateHandedOut:
		return "handed out"
	case HandoverStateIncoming:
		return "incoming"
	default:
		return "unknown"
	}
}

type RanUe struct {
	amfUeNgapId int64
	ranUeNgapId int64

	mobileIdentity5GS *ie.MobileId5GS

	ulTeid []byte
	dlTeid []byte

	n1Conn           net.Conn
	dataPlaneAddress *net.UDPAddr

	pduSessionEstablishmentCompleteChan    chan struct{}
	ueContextReleaseCompleteChan           chan struct{}
	pduSessionModifyIndicationCompleteChan chan struct{}

	nrdcIndicator    bool
	nrdcIndicatorMtx sync.Mutex

	ueSecurityCapabilities *ngapIe.UESecurityCapabilities

	handoverState    HandoverState
	handoverStateMtx sync.Mutex

	pathSwitchResultChan chan error
	handoverReleaseChan  chan error

	releaseOnce sync.Once
}

func NewRanUe(n1Conn net.Conn, ranUeNgapIdGenerator *RanUeNgapIdGenerator) (*RanUe, error) {
	ranUeId, err := ranUeNgapIdGenerator.AllocateRanUeId()
	if err != nil {
		return nil, err
	}

	return &RanUe{
		amfUeNgapId: -1,
		ranUeNgapId: ranUeId,

		mobileIdentity5GS: &ie.MobileId5GS{},

		n1Conn: n1Conn,

		pduSessionEstablishmentCompleteChan:    make(chan struct{}, 1),
		ueContextReleaseCompleteChan:           make(chan struct{}, 1),
		pduSessionModifyIndicationCompleteChan: make(chan struct{}, 1),

		nrdcIndicator:    false,
		nrdcIndicatorMtx: sync.Mutex{},

		handoverState: HandoverStateNone,

		pathSwitchResultChan: make(chan error, 1),
		handoverReleaseChan:  make(chan error, 1),
	}, nil
}

func (r *RanUe) Release(ranUeNgapIdGenerator *RanUeNgapIdGenerator, teidGenerator *TeidGenerator) error {
	var err error
	r.releaseOnce.Do(func() {
		ranUeNgapIdGenerator.ReleaseRanUeId(r.ranUeNgapId)
		if r.dlTeid != nil {
			err = teidGenerator.ReleaseTeid(r.dlTeid)
		}
	})
	return err
}

func (r *RanUe) GetAmfUeId() int64 {
	return r.amfUeNgapId
}

func (r *RanUe) GetRanUeId() int64 {
	return r.ranUeNgapId
}

func (r *RanUe) GetMobileIdentityIMSI() string {
	suci := r.mobileIdentity5GS.IdStr()
	parts := strings.Split(suci, "-")
	if len(parts) < 8 {
		return constant.UE_IMSI_PREFIX
	}

	// suci-0-mcc-mnc-routingInd-protectionScheme-homeNetworkPKI-schemeOutput
	return fmt.Sprintf("%s%s%s%s", constant.UE_IMSI_PREFIX, parts[2], parts[3], parts[7])
}

func (r *RanUe) GetIMSI() string {
	return r.GetMobileIdentityIMSI()
}

func (r *RanUe) GetUlTeid() []byte {
	return r.ulTeid
}

func (r *RanUe) GetDlTeid() []byte {
	return r.dlTeid
}

func (r *RanUe) GetN1Conn() net.Conn {
	return r.n1Conn
}

func (r *RanUe) GetDataPlaneAddress() *net.UDPAddr {
	return r.dataPlaneAddress
}

func (r *RanUe) SetAmfUeId(amfUeId int64) {
	r.amfUeNgapId = amfUeId
}

func (r *RanUe) SetRanUeId(ranUeId int64) {
	r.ranUeNgapId = ranUeId
}

func (r *RanUe) SetMobileIdentity5GS(mobileIdentity5GS *ie.MobileId5GS) {
	r.mobileIdentity5GS = mobileIdentity5GS
}

func (r *RanUe) SetUlTeid(ulTeid []byte) {
	r.ulTeid = ulTeid
}

func (r *RanUe) SetDlTeid(dlTeid []byte) {
	r.dlTeid = dlTeid
}

func (r *RanUe) SetDataPlaneAddress(dataPlaneAddress *net.UDPAddr) {
	r.dataPlaneAddress = dataPlaneAddress
}

func (r *RanUe) GetPduSessionEstablishmentCompleteChan() chan struct{} {
	return r.pduSessionEstablishmentCompleteChan
}

func (r *RanUe) GetUeContextReleaseCompleteChan() chan struct{} {
	return r.ueContextReleaseCompleteChan
}

func (r *RanUe) GetPduSessionModifyIndicationCompleteChan() chan struct{} {
	return r.pduSessionModifyIndicationCompleteChan
}

func (r *RanUe) SetN1Conn(n1Conn net.Conn) {
	r.n1Conn = n1Conn
}

func (r *RanUe) GetMobileIdentity5GS() *ie.MobileId5GS {
	return r.mobileIdentity5GS
}

func (r *RanUe) GetUeSecurityCapabilities() *ngapIe.UESecurityCapabilities {
	return r.ueSecurityCapabilities
}

func (r *RanUe) SetUeSecurityCapabilities(ueSecurityCapabilities *ngapIe.UESecurityCapabilities) {
	r.ueSecurityCapabilities = ueSecurityCapabilities
}

func (r *RanUe) GetPathSwitchResultChan() chan error {
	return r.pathSwitchResultChan
}

func (r *RanUe) GetHandoverReleaseChan() chan error {
	return r.handoverReleaseChan
}

func (r *RanUe) GetHandoverState() HandoverState {
	r.handoverStateMtx.Lock()
	defer r.handoverStateMtx.Unlock()
	return r.handoverState
}

func (r *RanUe) SetHandoverState(state HandoverState) {
	r.handoverStateMtx.Lock()
	defer r.handoverStateMtx.Unlock()
	r.handoverState = state
}

func (r *RanUe) CompareAndSetHandoverState(from, to HandoverState) bool {
	r.handoverStateMtx.Lock()
	defer r.handoverStateMtx.Unlock()
	if r.handoverState != from {
		return false
	}
	r.handoverState = to
	return true
}

func (r *RanUe) IsNrdcActivated() bool {
	r.nrdcIndicatorMtx.Lock()
	defer r.nrdcIndicatorMtx.Unlock()
	return r.nrdcIndicator
}

func (r *RanUe) ActivateNrdc() {
	r.nrdcIndicatorMtx.Lock()
	defer r.nrdcIndicatorMtx.Unlock()
	r.nrdcIndicator = true
}

func (r *RanUe) DeactivateNrdc() {
	r.nrdcIndicatorMtx.Lock()
	defer r.nrdcIndicatorMtx.Unlock()
	r.nrdcIndicator = false
}
