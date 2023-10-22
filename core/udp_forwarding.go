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
	dest         *tcpip.FullAddress
	destString   string
	ipStack      *stack.Stack
	client       *net.UDPAddr
	listenerConn *net.UDPConn

	connections      map[string]*connection
	connectionsMutex *sync.RWMutex

	connectCallback    func(addr string)
	disconnectCallback func(addr string)

	timeout time.Duration

	closed bool
}

type connection struct {
	available  chan struct{}
	udp        *gonet.UDPConn
	lastActive time.Time
}

func ServeUdpForwarding(bindAddress string, remoteAddress string, ipStack *stack.Stack) {
	udpForward := newUdpForward(bindAddress, remoteAddress, ipStack)
	udpForward.StartUdpForward()
}

func newUdpForward(src, dest string, ipStack *stack.Stack) *udpForward {
	u := new(udpForward)
	u.ipStack = ipStack
	u.connectCallback = func(addr string) {}
	u.disconnectCallback = func(addr string) {}
	u.connectionsMutex = new(sync.RWMutex)
	u.connections = make(map[string]*connection)
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

	u.dest = &tcpip.FullAddress{
		NIC:  defaultNIC,
		Port: uint16(port),
		Addr: tcpip.AddrFromSlice(net.ParseIP(host).To4()),
	}

	u.listenerConn, err = net.ListenUDP("udp", u.src)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return u
}

func (u *udpForward) StartUdpForward() {
	go u.janitor()
	for {
		buf := make([]byte, bufferSize)
		n, addr, err := u.listenerConn.ReadFromUDP(buf)
		if err != nil {
			log.Println("UDP forward: failed to read, terminating:", err)
			return
		}

		log.Printf("Port forwarding (udp): %s -> %s -> %s", addr.String(), u.src.String(), u.destString)
		go u.handle(buf[:n], addr)
	}
}

func (u *udpForward) janitor() {
	for !u.closed {
		time.Sleep(u.timeout)
		var keysToDelete []string

		u.connectionsMutex.RLock()
		for k, conn := range u.connections {
			if conn.lastActive.Before(time.Now().Add(-u.timeout)) {
				keysToDelete = append(keysToDelete, k)
			}
		}
		u.connectionsMutex.RUnlock()

		u.connectionsMutex.Lock()
		for _, k := range keysToDelete {
			u.connections[k].udp.Close()
			delete(u.connections, k)
		}
		u.connectionsMutex.Unlock()

		for _, k := range keysToDelete {
			u.disconnectCallback(k)
		}
	}
}

func (u *udpForward) handle(data []byte, addr *net.UDPAddr) {
	u.connectionsMutex.Lock()
	conn, found := u.connections[addr.String()]
	if !found {
		u.connections[addr.String()] = &connection{
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
			Port: u.dest.Port,
			Addr: u.dest.Addr,
		}

		udpConn, err = gonet.DialUDP(u.ipStack, nil, &addrTarget, header.IPv4ProtocolNumber)

		if err != nil {
			log.Println("UDP forward: failed to dial:", err)
			delete(u.connections, addr.String())
			return
		}

		u.connectionsMutex.Lock()
		u.connections[addr.String()].udp = udpConn
		u.connections[addr.String()].lastActive = time.Now()
		close(u.connections[addr.String()].available)
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
				delete(u.connections, addr.String())
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
	if _, found := u.connections[addr.String()]; found {
		if u.connections[addr.String()].lastActive.Before(
			time.Now().Add(u.timeout / 4)) {
			shouldChangeTime = true
		}
	}
	u.connectionsMutex.RUnlock()

	if shouldChangeTime {
		u.connectionsMutex.Lock()

		if _, found := u.connections[addr.String()]; found {
			connWrapper := u.connections[addr.String()]
			connWrapper.lastActive = time.Now()
			u.connections[addr.String()] = connWrapper
		}
		u.connectionsMutex.Unlock()
	}
}
