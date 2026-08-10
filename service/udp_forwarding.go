package service

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/stack"
)

const BufferSize = 40960
const DefaultTimeout = time.Minute * 5
const udpForwardQueueSize = 64
const defaultUDPForwardMaxConnections = 1024
const defaultUDPForwardMaxQueuedBytes int64 = 64 << 20

type UDPForward struct {
	src          *net.UDPAddr
	dest         *net.UDPAddr
	stack        stack.Stack
	listenerConn *net.UDPConn

	connections      map[netip.AddrPort]*UDPConnection
	connectionsMutex *sync.RWMutex
	connectionLRU    list.List

	connectCallback    func(addr string)
	disconnectCallback func(addr string)

	timeout time.Duration
	ctx     context.Context
	cancel  context.CancelFunc

	bufferPool     sync.Pool
	maxConnections int
	maxQueuedBytes int64
	queuedBytes    atomic.Int64
	wg             sync.WaitGroup
	closeOnce      sync.Once
	closeErr       error
}

type UDPConnection struct {
	ctx    context.Context
	cancel context.CancelFunc
	send   chan udpDatagram

	sendMu sync.RWMutex
	closed bool

	udpMu sync.Mutex
	udp   net.Conn

	lastActive atomic.Int64
	lruElement *list.Element
	closeOnce  sync.Once
}

type udpBuffer [BufferSize]byte

type udpDatagram struct {
	data           []byte
	buffer         *udpBuffer
	accountedBytes int64
}

func newUDPForward(vpnStack stack.Stack, src, dest string) *UDPForward {
	ctx, cancel := context.WithCancel(context.Background())
	u := &UDPForward{
		stack:              vpnStack,
		connectCallback:    func(string) {},
		disconnectCallback: func(string) {},
		connectionsMutex:   new(sync.RWMutex),
		connections:        make(map[netip.AddrPort]*UDPConnection),
		timeout:            DefaultTimeout,
		ctx:                ctx,
		cancel:             cancel,
		maxConnections:     defaultUDPForwardMaxConnections,
		maxQueuedBytes:     defaultUDPForwardMaxQueuedBytes,
	}
	u.bufferPool.New = func() any { return new(udpBuffer) }

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
	u.dest = &net.UDPAddr{IP: ip, Port: port}

	u.listenerConn, err = net.ListenUDP("udp", u.src)
	if err != nil {
		panic(err)
	}

	return u
}

func (u *UDPForward) startUDPForward() {
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		u.janitor()
	}()
	defer func() {
		_ = u.Close()
		u.wg.Wait()
	}()

	for {
		buf := u.getBuffer()
		n, addr, err := u.listenerConn.ReadFromUDP(buf[:])
		if err != nil {
			u.putBuffer(buf)
			if !errors.Is(err, net.ErrClosed) && u.ctx.Err() == nil {
				log.Println("UDP forward: failed to read, terminating:", err)
			}
			return
		}

		log.DebugPrintf("Port forwarding (UDP): %s -> %s -> %s", addr, u.src, u.dest)
		u.handleOwned(udpDatagram{data: buf[:n], buffer: buf}, addr)
	}
}

func (u *UDPForward) handle(data []byte, addr *net.UDPAddr) {
	buf := u.getBuffer()
	if len(data) > len(buf) {
		u.putBuffer(buf)
		u.handleOwned(udpDatagram{data: append([]byte(nil), data...)}, addr)
		return
	}
	copy(buf[:], data)
	u.handleOwned(udpDatagram{data: buf[:len(data)], buffer: buf}, addr)
}

func (u *UDPForward) handleOwned(data udpDatagram, addr *net.UDPAddr) {
	if !u.reserveDatagram(&data) {
		u.releaseDatagram(data)
		log.DebugPrintf("UDP forward: global queue budget exceeded for %s, dropping packet", addr)
		return
	}
	conn := u.getOrCreateConnection(addr)
	if !conn.enqueue(data) {
		u.releaseDatagram(data)
		log.DebugPrintf("UDP forward: send queue full for %s, dropping packet", addr)
	}
}

func (u *UDPForward) getOrCreateConnection(addr *net.UDPAddr) *UDPConnection {
	key := addr.AddrPort()
	u.connectionsMutex.Lock()
	if conn := u.connections[key]; conn != nil {
		u.markConnectionActiveLocked(key, conn)
		u.connectionsMutex.Unlock()
		return conn
	}
	evicted := u.makeRoomForConnectionLocked()
	ctx, cancel := context.WithCancel(u.ctx)
	conn := &UDPConnection{
		ctx:    ctx,
		cancel: cancel,
		send:   make(chan udpDatagram, udpForwardQueueSize),
	}
	u.connections[key] = conn
	u.markConnectionActiveLocked(key, conn)
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		u.runConnection(key, cloneUDPAddr(addr), conn)
	}()
	u.connectionsMutex.Unlock()
	if evicted != nil {
		evicted.close()
	}
	return conn
}

func (u *UDPForward) makeRoomForConnectionLocked() *UDPConnection {
	if u.maxConnections <= 0 || len(u.connections) < u.maxConnections {
		return nil
	}
	oldestElement := u.connectionLRU.Front()
	if oldestElement == nil {
		return nil
	}
	oldestKey := oldestElement.Value.(netip.AddrPort)
	oldest := u.connections[oldestKey]
	delete(u.connections, oldestKey)
	u.connectionLRU.Remove(oldestElement)
	oldest.lruElement = nil
	return oldest
}

func (u *UDPForward) runConnection(key netip.AddrPort, clientAddr *net.UDPAddr, conn *UDPConnection) {
	connected := false
	defer func() {
		conn.close()
		u.removeConnection(key, conn)
		for {
			select {
			case data := <-conn.send:
				u.releaseDatagram(data)
			default:
				if connected {
					u.disconnectCallback(key.String())
				}
				return
			}
		}
	}()

	udpConn, err := u.stack.DialUDP(conn.ctx, cloneUDPAddr(u.dest))
	if err != nil {
		if conn.ctx.Err() == nil {
			log.Println("UDP forward: failed to dial:", err)
		}
		return
	}
	if !conn.setUDP(udpConn) {
		return
	}
	connected = true
	u.connectCallback(key.String())

	readDone := make(chan error, 1)
	go func() {
		readDone <- u.forwardResponses(key, conn, udpConn, clientAddr)
	}()
	readFinished := false
	defer func() {
		conn.close()
		if !readFinished {
			<-readDone
		}
	}()

	for {
		select {
		case data := <-conn.send:
			_, err := udpConn.Write(data.data)
			u.releaseDatagram(data)
			if err != nil {
				if conn.ctx.Err() == nil {
					log.Println("UDP forward: error sending packet to server:", err)
				}
				return
			}
		case err := <-readDone:
			readFinished = true
			if err != nil && conn.ctx.Err() == nil {
				log.Println("UDP forward: abnormal read, closing:", err)
			}
			return
		case <-conn.ctx.Done():
			return
		}
	}
}

func (u *UDPForward) forwardResponses(key netip.AddrPort, conn *UDPConnection, udpConn net.Conn, clientAddr *net.UDPAddr) error {
	buf := u.getBuffer()
	defer u.putBuffer(buf)
	for {
		n, err := udpConn.Read(buf[:])
		if err != nil {
			return err
		}
		u.markConnectionActive(key, conn)
		if _, err := u.listenerConn.WriteToUDP(buf[:n], clientAddr); err != nil {
			return err
		}
	}
}

func (u *UDPForward) removeConnection(key netip.AddrPort, conn *UDPConnection) {
	u.connectionsMutex.Lock()
	if u.connections[key] == conn {
		delete(u.connections, key)
		if conn.lruElement != nil {
			u.connectionLRU.Remove(conn.lruElement)
			conn.lruElement = nil
		}
	}
	u.connectionsMutex.Unlock()
}

func (u *UDPForward) markConnectionActive(key netip.AddrPort, conn *UDPConnection) {
	u.connectionsMutex.Lock()
	if u.connections[key] == conn {
		u.markConnectionActiveLocked(key, conn)
	}
	u.connectionsMutex.Unlock()
}

func (u *UDPForward) markConnectionActiveLocked(key netip.AddrPort, conn *UDPConnection) {
	conn.touch()
	if conn.lruElement == nil {
		conn.lruElement = u.connectionLRU.PushBack(key)
		return
	}
	u.connectionLRU.MoveToBack(conn.lruElement)
}

func (u *UDPForward) janitor() {
	interval := u.timeout / 4
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case now := <-ticker.C:
			cutoff := now.Add(-u.timeout).UnixNano()
			u.connectionsMutex.RLock()
			stale := make([]*UDPConnection, 0)
			for _, conn := range u.connections {
				if conn.lastActive.Load() < cutoff {
					stale = append(stale, conn)
				}
			}
			u.connectionsMutex.RUnlock()
			for _, conn := range stale {
				conn.close()
			}
		}
	}
}

func (u *UDPForward) getBuffer() *udpBuffer {
	return u.bufferPool.Get().(*udpBuffer)
}

func (u *UDPForward) putBuffer(buf *udpBuffer) {
	u.bufferPool.Put(buf)
}

func (u *UDPForward) releaseDatagram(data udpDatagram) {
	if data.accountedBytes > 0 {
		u.queuedBytes.Add(-data.accountedBytes)
	}
	if data.buffer != nil {
		u.putBuffer(data.buffer)
	}
}

func (u *UDPForward) reserveDatagram(data *udpDatagram) bool {
	if u.maxQueuedBytes <= 0 {
		return true
	}
	bytes := int64(len(data.data))
	if data.buffer != nil {
		bytes = BufferSize
	}
	for {
		used := u.queuedBytes.Load()
		if bytes > u.maxQueuedBytes-used {
			return false
		}
		if u.queuedBytes.CompareAndSwap(used, used+bytes) {
			data.accountedBytes = bytes
			return true
		}
	}
}

func (u *UDPForward) Close() error {
	u.closeOnce.Do(func() {
		u.cancel()
		if u.listenerConn != nil {
			u.closeErr = u.listenerConn.Close()
		}
		u.connectionsMutex.RLock()
		connections := make([]*UDPConnection, 0, len(u.connections))
		for _, conn := range u.connections {
			connections = append(connections, conn)
		}
		u.connectionsMutex.RUnlock()
		for _, conn := range connections {
			conn.close()
		}
	})
	return u.closeErr
}

func (c *UDPConnection) enqueue(data udpDatagram) bool {
	c.sendMu.RLock()
	defer c.sendMu.RUnlock()
	if c.closed {
		return false
	}
	select {
	case c.send <- data:
		c.touch()
		return true
	default:
		return false
	}
}

func (c *UDPConnection) setUDP(conn net.Conn) bool {
	c.udpMu.Lock()
	defer c.udpMu.Unlock()
	if c.ctx.Err() != nil {
		_ = conn.Close()
		return false
	}
	c.udp = conn
	return true
}

func (c *UDPConnection) touch() {
	c.lastActive.Store(time.Now().UnixNano())
}

func (c *UDPConnection) close() {
	c.closeOnce.Do(func() {
		c.sendMu.Lock()
		c.closed = true
		c.cancel()
		c.sendMu.Unlock()
		c.udpMu.Lock()
		if c.udp != nil {
			_ = c.udp.Close()
		}
		c.udpMu.Unlock()
	})
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	clone := *addr
	clone.IP = append(net.IP(nil), addr.IP...)
	return &clone
}

func ServeUDPForwarding(vpnStack stack.Stack, bindAddress string, remoteAddress string) {
	log.Printf("UDP port forwarding: %s -> %s", bindAddress, remoteAddress)

	udpForward := newUDPForward(vpnStack, bindAddress, remoteAddress)

	hook_func.RegisterTerminalFunc("CloseUDPForwardingPort", func(ctx context.Context) error {
		log.Println("Closing UDP forwarding port...")
		if err := udpForward.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("close UDP forwarding listener failed: %w", err)
		}
		return nil
	})

	udpForward.startUDPForward()
}
