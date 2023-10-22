package core

import (
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const defaultNIC tcpip.NICID = 1
const defaultMTU uint32 = 1400

// implements LinkEndpoint
type EasyConnectGvisorEndpoint struct {
	dispatcher stack.NetworkDispatcher
	OnRecv     func(buf []byte)
}

func (ep *EasyConnectGvisorEndpoint) ParseHeader(ptr stack.PacketBufferPtr) bool {
	return true
}

func (ep *EasyConnectGvisorEndpoint) MTU() uint32 {
	return defaultMTU
}

func (ep *EasyConnectGvisorEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (ep *EasyConnectGvisorEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (ep *EasyConnectGvisorEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (ep *EasyConnectGvisorEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.dispatcher = dispatcher
}

func (ep *EasyConnectGvisorEndpoint) IsAttached() bool {
	return ep.dispatcher != nil
}

func (ep *EasyConnectGvisorEndpoint) Wait() {}

func (ep *EasyConnectGvisorEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *EasyConnectGvisorEndpoint) AddHeader(stack.PacketBufferPtr) {}

func (ep *EasyConnectGvisorEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	for _, packetBuffer := range list.AsSlice() {
		var buf []byte
		for _, t := range packetBuffer.AsSlices() {
			buf = append(buf, t...)
		}

		if ep.OnRecv != nil {
			ep.OnRecv(buf)
		}
	}
	return list.Len(), nil
}

func (ep *EasyConnectGvisorEndpoint) WriteTo(buf []byte) {
	if ep.IsAttached() {
		packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(buf),
		})
		ep.dispatcher.DeliverNetworkPacket(header.IPv4ProtocolNumber, packetBuffer)
		packetBuffer.DecRef()
	}
}

func SetupGvisorStack(ip []byte, endpoint *EasyConnectGvisorEndpoint) *stack.Stack {

	// init IP stack
	ipStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	})

	// create NIC associated to the gvisorEndpoint
	err := ipStack.CreateNIC(defaultNIC, endpoint)
	if err != nil {
		panic(err)
	}

	// assign ip
	addr := tcpip.AddrFromSlice(ip)
	protoAddr := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: 32,
		},
		Protocol: ipv4.ProtocolNumber,
	}

	err = ipStack.AddProtocolAddress(defaultNIC, protoAddr, stack.AddressProperties{})
	if err != nil {
		panic(err)
	}

	// other settings
	sOpt := tcpip.TCPSACKEnabled(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	cOpt := tcpip.CongestionControlOption("cubic")
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &cOpt)
	ipStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: defaultNIC})

	return ipStack
}
