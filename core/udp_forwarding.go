package core

import (
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const bufferSize = 40960
const DefaultTimeout = time.Minute * 5

type udpForward struct {
	src          *net.UDPAddr
	destHost     net.IP
	destPort     int
	destString   string
	ipStack      *stack.Stack
	client       *net.UDPAddr
	listenerConn *net.UDPConn

	gvisorConnections map[string]*gvisorConnection
	tunConnections    map[string]*tunConnection
	connectionsMutex  *sync.RWMutex

	connectCallback    func(addr string)
	disconnectCallback func(addr string)

	timeout time.Duration

	closed bool
}

type gvisorConnection struct {
	available  chan struct{}
	udp        *gonet.UDPConn
	lastActive time.Time
}

type tunConnection struct {
	available  chan struct{}
	udp        *net.UDPConn
	lastActive time.Time
}

func ServeUdpForwarding(bindAddress string, remoteAddress string, client *EasyConnectClient) {
	udpForward := newUdpForward(bindAddress, remoteAddress, client)
	if TunMode {
		udpForward.StartUdpForwardWithTun()
	} else {
		udpForward.StartUdpForwardWithGvisor()
	}
}

func newUdpForward(src, dest string, client *EasyConnectClient) *udpForward {
	u := new(udpForward)
	u.ipStack = client.gvisorStack
	u.connectCallback = func(addr string) {}
	u.disconnectCallback = func(addr string) {}
	u.connectionsMutex = new(sync.RWMutex)

	if TunMode {
		u.tunConnections = make(map[string]*tunConnection)
	} else {
		u.gvisorConnections = make(map[string]*gvisorConnection)
	}

	u.timeout = DefaultTimeout

	var err error
	u.src, err = net.ResolveUDPAddr("udp", src)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	parts := strings.Split(dest, ":")
	host := parts[0]
	port, err := strconv.Atoi(parts[1])

	u.destString = dest

	u.destHost = net.ParseIP(host)
	u.destPort = port

	u.listenerConn, err = net.ListenUDP("udp", u.src)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return u
}

func (u *udpForward) StartUdpForwardWithGvisor() {
	go u.janitorWithGvisor()
	for {
		buf := make([]byte, bufferSize)
		n, addr, err := u.listenerConn.ReadFromUDP(buf)
		if err != nil {
			log.Println("UDP forward: failed to read, terminating:", err)
			return
		}

		log.Printf("Port forwarding (udp): %s -> %s -> %s", addr.String(), u.src.String(), u.destString)
		go u.handleWithGvisor(buf[:n], addr)
	}
}

func (u *udpForward) janitorWithGvisor() {
	for !u.closed {
		time.Sleep(u.timeout)
		var keysToDelete []string

		u.connectionsMutex.RLock()
		for k, conn := range u.gvisorConnections {
			if conn.lastActive.Before(time.Now().Add(-u.timeout)) {
				keysToDelete = append(keysToDelete, k)
			}
		}
		u.connectionsMutex.RUnlock()

		u.connectionsMutex.Lock()
		for _, k := range keysToDelete {
			u.gvisorConnections[k].udp.Close()
			delete(u.gvisorConnections, k)
		}
		u.connectionsMutex.Unlock()

		for _, k := range keysToDelete {
			u.disconnectCallback(k)
		}
	}
}

func (u *udpForward) handleWithGvisor(data []byte, addr *net.UDPAddr) {
	u.connectionsMutex.Lock()
	conn, found := u.gvisorConnections[addr.String()]
	if !found {
		u.gvisorConnections[addr.String()] = &gvisorConnection{
			available:  make(chan struct{}),
			udp:        nil,
			lastActive: time.Now(),
		}
	}
	u.connectionsMutex.Unlock()

	if !found {
		var udpConn *gonet.UDPConn
		var err error

		addrTarget := tcpip.FullAddress{
			NIC:  defaultNIC,
			Port: uint16(u.destPort),
			Addr: tcpip.AddrFromSlice(u.destHost.To4()),
		}

		udpConn, err = gonet.DialUDP(u.ipStack, nil, &addrTarget, header.IPv4ProtocolNumber)

		if err != nil {
			log.Println("UDP forward: failed to dial:", err)
			delete(u.gvisorConnections, addr.String())
			return
		}

		u.connectionsMutex.Lock()
		u.gvisorConnections[addr.String()].udp = udpConn
		u.gvisorConnections[addr.String()].lastActive = time.Now()
		close(u.gvisorConnections[addr.String()].available)
		u.connectionsMutex.Unlock()

		u.connectCallback(addr.String())

		_, err = udpConn.Write(data)
		if err != nil {
			log.Println("UDP forward: error sending initial packet to client", err)
		}

		for {
			buf := make([]byte, bufferSize)
			n, err := udpConn.Read(buf)
			if err != nil {
				u.connectionsMutex.Lock()
				udpConn.Close()
				delete(u.gvisorConnections, addr.String())
				u.connectionsMutex.Unlock()
				u.disconnectCallback(addr.String())
				log.Println("udp-forward: abnormal read, closing:", err)
				return
			}

			_, _, err = u.listenerConn.WriteMsgUDP(buf[:n], nil, addr)
			if err != nil {
				log.Println("UDP forward: error sending packet to client:", err)
			}
		}
	}

	<-conn.available

	_, err := conn.udp.Write(data)
	if err != nil {
		log.Println("UDP forward: error sending packet to server:", err)
	}

	shouldChangeTime := false
	u.connectionsMutex.RLock()
	if _, found := u.gvisorConnections[addr.String()]; found {
		if u.gvisorConnections[addr.String()].lastActive.Before(
			time.Now().Add(u.timeout / 4)) {
			shouldChangeTime = true
		}
	}
	u.connectionsMutex.RUnlock()

	if shouldChangeTime {
		u.connectionsMutex.Lock()

		if _, found := u.gvisorConnections[addr.String()]; found {
			connWrapper := u.gvisorConnections[addr.String()]
			connWrapper.lastActive = time.Now()
			u.gvisorConnections[addr.String()] = connWrapper
		}
		u.connectionsMutex.Unlock()
	}
}

func (u *udpForward) StartUdpForwardWithTun() {
	go u.janitorWithTun()
	for {
		buf := make([]byte, bufferSize)
		n, addr, err := u.listenerConn.ReadFromUDP(buf)
		if err != nil {
			log.Println("UDP forward: failed to read, terminating:", err)
			return
		}

		log.Printf("Port forwarding (udp): %s -> %s -> %s", addr.String(), u.src.String(), u.destString)
		go u.handleWithTun(buf[:n], addr)
	}
}

func (u *udpForward) janitorWithTun() {
	for !u.closed {
		time.Sleep(u.timeout)
		var keysToDelete []string

		u.connectionsMutex.RLock()
		for k, conn := range u.tunConnections {
			if conn.lastActive.Before(time.Now().Add(-u.timeout)) {
				keysToDelete = append(keysToDelete, k)
			}
		}
		u.connectionsMutex.RUnlock()

		u.connectionsMutex.Lock()
		for _, k := range keysToDelete {
			u.tunConnections[k].udp.Close()
			delete(u.tunConnections, k)
		}
		u.connectionsMutex.Unlock()

		for _, k := range keysToDelete {
			u.disconnectCallback(k)
		}
	}
}

func (u *udpForward) handleWithTun(data []byte, addr *net.UDPAddr) {
	u.connectionsMutex.Lock()
	conn, found := u.tunConnections[addr.String()]
	if !found {
		u.tunConnections[addr.String()] = &tunConnection{
			available:  make(chan struct{}),
			udp:        nil,
			lastActive: time.Now(),
		}
	}
	u.connectionsMutex.Unlock()

	if !found {
		var udpConn *net.UDPConn
		var err error

		addrTarget := net.UDPAddr{
			IP:   u.destHost,
			Port: u.destPort,
		}

		udpConn, err = net.DialUDP("udp", nil, &addrTarget)

		if err != nil {
			log.Println("UDP forward: failed to dial:", err)
			delete(u.tunConnections, addr.String())
			return
		}

		u.connectionsMutex.Lock()
		u.tunConnections[addr.String()].udp = udpConn
		u.tunConnections[addr.String()].lastActive = time.Now()
		close(u.tunConnections[addr.String()].available)
		u.connectionsMutex.Unlock()

		u.connectCallback(addr.String())

		_, err = udpConn.Write(data)
		if err != nil {
			log.Println("UDP forward: error sending initial packet to client", err)
		}

		for {
			buf := make([]byte, bufferSize)
			n, err := udpConn.Read(buf)
			if err != nil {
				u.connectionsMutex.Lock()
				udpConn.Close()
				delete(u.tunConnections, addr.String())
				u.connectionsMutex.Unlock()
				u.disconnectCallback(addr.String())
				log.Println("udp-forward: abnormal read, closing:", err)
				return
			}

			_, _, err = u.listenerConn.WriteMsgUDP(buf[:n], nil, addr)
			if err != nil {
				log.Println("UDP forward: error sending packet to client:", err)
			}
		}
	}

	<-conn.available

	_, err := conn.udp.Write(data)
	if err != nil {
		log.Println("UDP forward: error sending packet to server:", err)
	}

	shouldChangeTime := false
	u.connectionsMutex.RLock()
	if _, found := u.tunConnections[addr.String()]; found {
		if u.tunConnections[addr.String()].lastActive.Before(
			time.Now().Add(u.timeout / 4)) {
			shouldChangeTime = true
		}
	}
	u.connectionsMutex.RUnlock()

	if shouldChangeTime {
		u.connectionsMutex.Lock()

		if _, found := u.tunConnections[addr.String()]; found {
			connWrapper := u.tunConnections[addr.String()]
			connWrapper.lastActive = time.Now()
			u.tunConnections[addr.String()] = connWrapper
		}
		u.connectionsMutex.Unlock()
	}
}
