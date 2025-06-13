package atrust

import (
	"github.com/mythologyli/zju-connect/client"
	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/internal/zcdns"
	"github.com/mythologyli/zju-connect/log"
)

type Stack struct {
	username string
	sid      string
	deviceID string
	signKey  string

	ipResources     []client.IPResource
	domainResources map[string]client.DomainResource

	nodeGroups map[string][]string

	resolve zcdns.LocalServer
}

func NewStack(aTrustClient *atrustclient.Client) *Stack {
	stack := Stack{
		username: aTrustClient.Username,
		sid:      aTrustClient.SID,
		deviceID: aTrustClient.DeviceID,
		signKey:  aTrustClient.SignKey,
	}

	ipResources, err := aTrustClient.IPResources()
	if ipResources == nil {
		ipResources = []client.IPResource{}
	}
	stack.ipResources = ipResources

	domainResources, err := aTrustClient.DomainResources()
	if err != nil {
		domainResources = make(map[string]client.DomainResource)
	}
	stack.domainResources = domainResources

	stack.nodeGroups = aTrustClient.NodeGroups
	if stack.nodeGroups == nil {
		log.Fatalf("No node group list found")
	}

	return &stack
}

func (s *Stack) SetupResolve(r zcdns.LocalServer) {
	s.resolve = r
}

func (s *Stack) Run() {

}
