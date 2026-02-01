package tun

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const NICID tcpip.NICID = 2

type TCPListenerEndpoint struct {
	tunEndpoint *Endpoint
	dispatcher  stack.NetworkDispatcher
}

func (ep *TCPListenerEndpoint) ParseHeader(*stack.PacketBuffer) bool {
	return true
}

func (ep *TCPListenerEndpoint) MTU() uint32 { return MTU }

func (ep *TCPListenerEndpoint) SetMTU(mtu uint32) {
	log.Println("don't support change MTU from %d to %d", MTU, mtu)
}

func (ep *TCPListenerEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (ep *TCPListenerEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (ep *TCPListenerEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {}

func (ep *TCPListenerEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (ep *TCPListenerEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.dispatcher = dispatcher
}

func (ep *TCPListenerEndpoint) IsAttached() bool {
	return ep.dispatcher != nil
}

func (ep *TCPListenerEndpoint) Wait() {}

func (ep *TCPListenerEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *TCPListenerEndpoint) AddHeader(*stack.PacketBuffer) {}

func (ep *TCPListenerEndpoint) Close() {}

func (ep *TCPListenerEndpoint) SetOnCloseAction(func()) {}

func (ep *TCPListenerEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	for _, packetBuffer := range list.AsSlice() {
		var buf []byte
		for _, t := range packetBuffer.AsSlices() {
			buf = append(buf, t...)
		}

		if ep.tunEndpoint != nil {
			err := ep.tunEndpoint.Write(buf)
			if err != nil {
				if hook_func.IsTerminal() {
					return 0, &tcpip.ErrAborted{}
				}

				log.Printf("Error occurred while writing from TCP listener stack to TUN stack: %v", err)
				return 0, &tcpip.ErrAborted{}
			}
		}
	}

	return list.Len(), nil
}

func (s *Stack) CreateTCPListener() error {
	s.tcpListenerEndpoint = &TCPListenerEndpoint{
		tunEndpoint: s.endpoint,
	}
	s.tcpListenerStack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	if err := s.tcpListenerStack.CreateNIC(NICID, s.tcpListenerEndpoint); err != nil {
		return fmt.Errorf("error creating NIC %d: %v", NICID, err)
	}
	s.tcpListenerStack.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)
	s.tcpListenerStack.SetPromiscuousMode(NICID, true)
	s.tcpListenerStack.SetSpoofing(NICID, true)
	s.tcpListenerStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: NICID})
	sOpt := tcpip.TCPSACKEnabled(true)
	s.tcpListenerStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)

	return nil
}

func (s *Stack) StartTCPListener() {
	forwarder := tcp.NewForwarder(s.tcpListenerStack, 0, 10000, func(r *tcp.ForwarderRequest) {
		outboundAddr := r.ID().LocalAddress.String()
		outboundPort := r.ID().LocalPort

		log.DebugPrintf("[tcp listener] new connection to %s:%d", outboundAddr, outboundPort)

		var w waiter.Queue
		ep, err := r.CreateEndpoint(&w)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		localConn := gonet.NewTCPConn(&w, ep)
		go s.handleInboundConn(localConn, outboundAddr, outboundPort)
	})
	s.tcpListenerStack.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
}

func (s *Stack) handleInboundConn(lConn net.Conn, targetIP string, targetPort uint16) {
	defer func(lConn net.Conn) {
		_ = lConn.Close()
	}(lConn)

	targetAddr := fmt.Sprintf("%s:%d", targetIP, targetPort)
	addr, err := net.ResolveTCPAddr("tcp", targetAddr)
	if err != nil {
		return
	}
	remoteConn, err := s.endpoint.client.DialTCP(context.Background(), addr)
	if err != nil {
		log.Printf("Error dialing remote TCP %s via tunnel: %v", targetAddr, err)
		return
	}
	defer func(remoteConn net.Conn) {
		_ = remoteConn.Close()
	}(remoteConn)

	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(remoteConn, lConn); errCh <- err }()
	go func() { _, err := io.Copy(lConn, remoteConn); errCh <- err }()
	<-errCh
}
