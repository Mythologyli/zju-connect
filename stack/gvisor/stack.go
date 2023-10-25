package gvisor

import (
	"errors"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/log"
	"github.com/refraction-networking/utls"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type Stack struct {
	gvisorStack *stack.Stack

	endpoint *Endpoint
}

const NICID tcpip.NICID = 1
const MTU uint32 = 1400

type Endpoint struct {
	easyConnectClient *client.EasyConnectClient

	sendConn     *tls.UConn
	recvConn     *tls.UConn
	sendErrCount int
	recvErrCount int

	dispatcher stack.NetworkDispatcher
}

func (ep *Endpoint) ParseHeader(stack.PacketBufferPtr) bool {
	return true
}

func (ep *Endpoint) MTU() uint32 {
	return MTU
}

func (ep *Endpoint) MaxHeaderLength() uint16 {
	return 0
}

func (ep *Endpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (ep *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (ep *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.dispatcher = dispatcher
}

func (ep *Endpoint) IsAttached() bool {
	return ep.dispatcher != nil
}

func (ep *Endpoint) Wait() {}

func (ep *Endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *Endpoint) AddHeader(stack.PacketBufferPtr) {}

// WritePackets is called when get packets from gVisor stack. Then it sends them to VPN server
func (ep *Endpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	for _, packetBuffer := range list.AsSlice() {
		var buf []byte
		for _, t := range packetBuffer.AsSlices() {
			buf = append(buf, t...)
		}

		if ep.sendConn != nil {
			n, err := ep.sendConn.Write(buf)
			if err != nil {
				if ep.sendErrCount < 5 {
					log.Printf("Error occurred while sending, retrying: %v", err)

					// Do handshake again and create a new sendConn
					ep.sendConn.Close()
					ep.sendConn, err = ep.easyConnectClient.SendConn()
					if err != nil {
						panic(err)
					}
				} else {
					panic("send retry limit exceeded.")
				}

				ep.sendErrCount++
			} else {
				log.DebugPrintf("Send: wrote %d bytes", n)
				log.DebugDumpHex(buf[:n])
			}
		}
	}

	return list.Len(), nil
}

func NewStack(easyConnectClient *client.EasyConnectClient) (*Stack, error) {
	s := &Stack{}

	s.gvisorStack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	})

	s.endpoint = &Endpoint{
		easyConnectClient: easyConnectClient,
	}

	tcpipErr := s.gvisorStack.CreateNIC(NICID, s.endpoint)
	if tcpipErr != nil {
		return nil, errors.New(tcpipErr.String())
	}

	ip, err := easyConnectClient.IP()
	if err != nil {
		return nil, err
	}

	addr := tcpip.AddrFromSlice(ip)
	protoAddr := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: 32,
		},
		Protocol: ipv4.ProtocolNumber,
	}

	tcpipErr = s.gvisorStack.AddProtocolAddress(NICID, protoAddr, stack.AddressProperties{})
	if tcpipErr != nil {
		return nil, errors.New(tcpipErr.String())
	}

	sOpt := tcpip.TCPSACKEnabled(true)
	s.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	cOpt := tcpip.CongestionControlOption("cubic")
	s.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber, &cOpt)
	s.gvisorStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: NICID})

	return s, nil
}

func (s *Stack) Run() {
	var err error
	s.endpoint.sendConn, err = s.endpoint.easyConnectClient.SendConn()
	if err != nil {
		panic(err)
	}

	s.endpoint.recvConn, err = s.endpoint.easyConnectClient.RecvConn()
	if err != nil {
		panic(err)
	}

	// Read from VPN server and send to gVisor stack
	for {
		buf := make([]byte, 1500)
		n, err := s.endpoint.recvConn.Read(buf)
		if err != nil {
			if s.endpoint.recvErrCount < 5 {
				log.Printf("Error occurred while receiving, retrying: %v", err)

				// Do handshake again and create a new recvConn
				s.endpoint.recvConn.Close()
				s.endpoint.recvConn, err = s.endpoint.easyConnectClient.RecvConn()
				if err != nil {
					panic(err)
				}
			} else {
				panic("recv retry limit exceeded.")
			}

			s.endpoint.recvErrCount++
		} else {
			log.DebugPrintf("Recv: read %d bytes", n)
			log.DebugDumpHex(buf[:n])

			packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(buf),
			})
			s.endpoint.dispatcher.DeliverNetworkPacket(header.IPv4ProtocolNumber, packetBuffer)
			packetBuffer.DecRef()
		}
	}
}
