package service

import (
	"context"
	"fmt"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/stack"
	"net"
	"strconv"
	"sync"
	"time"
)

const BufferSize = 40960
const DefaultTimeout = time.Minute * 5

type UDPForward struct {
	src          *net.UDPAddr
	dest         *net.UDPAddr
	stack        stack.Stack
	client       *net.UDPAddr
	listenerConn *net.UDPConn

	connections      map[string]*UDPConnection
	connectionsMutex *sync.RWMutex

	connectCallback    func(addr string)
	disconnectCallback func(addr string)

	timeout time.Duration

	closed bool
}

type UDPConnection struct {
	available  chan struct{}
	udp        net.Conn
	lastActive time.Time
}

func newUDPForward(stack stack.Stack, src, dest string) *UDPForward {
	u := new(UDPForward)
	u.stack = stack
	u.connectCallback = func(addr string) {}
	u.disconnectCallback = func(addr string) {}
	u.connectionsMutex = new(sync.RWMutex)
	u.connections = make(map[string]*UDPConnection)
	u.timeout = DefaultTimeout

	var err error
	u.src, err = net.ResolveUDPAddr("udp", src)
	if err != nil {
		panic(err)
	}

	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		panic(err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		panic(err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		panic(fmt.Errorf("invalid host: %s", host))
	}

	u.dest = &net.UDPAddr{
		IP:   ip,
		Port: port,
	}

	u.listenerConn, err = net.ListenUDP("udp", u.src)
	if err != nil {
		panic(err)
	}

	return u
}

func (u *UDPForward) startUDPForward() {
	go u.janitor()
	for {
		buf := make([]byte, BufferSize)
		n, addr, err := u.listenerConn.ReadFromUDP(buf)
		if err != nil {
			log.Println("UDP forward: failed to read, terminating:", err)
			return
		}

		log.Printf("Port forwarding (UDP): %s -> %s -> %s", addr.String(), u.src.String(), u.dest.String())
		go u.handle(buf[:n], addr)
	}
}

func (u *UDPForward) janitor() {
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

func (u *UDPForward) handle(data []byte, addr *net.UDPAddr) {
	u.connectionsMutex.Lock()
	conn, found := u.connections[addr.String()]
	if !found {
		u.connections[addr.String()] = &UDPConnection{
			available:  make(chan struct{}),
			udp:        nil,
			lastActive: time.Now(),
		}
	}
	u.connectionsMutex.Unlock()

	if !found {
		var udpConn net.Conn
		var err error

		udpConn, err = u.stack.DialUDP(context.Background(), &net.UDPAddr{
			IP:   u.dest.IP,
			Port: u.dest.Port,
		})

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
			buf := make([]byte, BufferSize)
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

func ServeUDPForwarding(stack stack.Stack, bindAddress string, remoteAddress string) {
	log.Printf("UDP port forwarding: %s -> %s", bindAddress, remoteAddress)

	udpForward := newUDPForward(stack, bindAddress, remoteAddress)
	udpForward.startUDPForward()
}
