package underlay

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	pcapLinkTypeRaw     = 101
	maxTCPPayload       = 60_000
	pcapEventQueueSize  = 256
	pcapWriteBufferSize = 256 << 10
)

type captureDirection uint8

const (
	captureOutgoing captureDirection = iota
	captureIncoming
)

type captureEvent struct {
	connID    uint32
	direction captureDirection
	timestamp time.Time
	local     *net.TCPAddr
	remote    *net.TCPAddr
	payload   []byte
}

type pcapCapture struct {
	file   *os.File
	events chan captureEvent
	done   chan struct{}

	stateMu   sync.RWMutex
	closed    bool
	closeOnce sync.Once
	nextID    atomic.Uint32
	writeErr  error
}

func newPCAPCapture(path string) (*pcapCapture, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := writePCAPGlobalHeader(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	capture := &pcapCapture{
		file:   file,
		events: make(chan captureEvent, pcapEventQueueSize),
		done:   make(chan struct{}),
	}
	go capture.writeLoop()
	return capture, nil
}

func writePCAPGlobalHeader(file *os.File) error {
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], 65_535)
	binary.LittleEndian.PutUint32(header[20:24], pcapLinkTypeRaw)
	_, err := file.Write(header)
	return err
}

func (c *pcapCapture) Wrap(conn net.Conn) net.Conn {
	local, localOK := conn.LocalAddr().(*net.TCPAddr)
	remote, remoteOK := conn.RemoteAddr().(*net.TCPAddr)
	if !localOK || !remoteOK || local.IP == nil || remote.IP == nil {
		return conn
	}
	c.stateMu.RLock()
	closed := c.closed
	c.stateMu.RUnlock()
	if closed {
		return conn
	}
	return &pcapConn{
		Conn:    conn,
		capture: c,
		connID:  c.nextID.Add(1),
		local:   cloneTCPAddr(local),
		remote:  cloneTCPAddr(remote),
	}
}

func cloneTCPAddr(addr *net.TCPAddr) *net.TCPAddr {
	clone := *addr
	clone.IP = append(net.IP(nil), addr.IP...)
	return &clone
}

// enqueue deliberately blocks when the bounded queue is full. Capture is a
// debug feature, so preserving the byte stream takes precedence over latency.
func (c *pcapCapture) enqueue(event captureEvent) error {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	if c.closed {
		return os.ErrClosed
	}
	c.events <- event
	return nil
}

func (c *pcapCapture) writeLoop() {
	defer close(c.done)
	writer := bufio.NewWriterSize(c.file, pcapWriteBufferSize)
	streams := make(map[uint32]*pcapStreamState)
	for event := range c.events {
		if c.writeErr != nil {
			continue
		}
		stream := streams[event.connID]
		if stream == nil {
			base := event.connID << 20
			stream = &pcapStreamState{sendSeq: base + 1, receiveSeq: base + 1<<19}
			streams[event.connID] = stream
		}
		packet, err := stream.packet(event)
		if err == nil {
			err = writePCAPPacket(writer, packet, event.timestamp)
		}
		if err != nil {
			c.writeErr = err
		}
	}
	c.writeErr = errors.Join(c.writeErr, writer.Flush(), c.file.Close())
}

func writePCAPPacket(writer *bufio.Writer, packet []byte, timestamp time.Time) error {
	record := make([]byte, 16)
	binary.LittleEndian.PutUint32(record[0:4], uint32(timestamp.Unix()))
	binary.LittleEndian.PutUint32(record[4:8], uint32(timestamp.Nanosecond()/1_000))
	binary.LittleEndian.PutUint32(record[8:12], uint32(len(packet)))
	binary.LittleEndian.PutUint32(record[12:16], uint32(len(packet)))
	if _, err := writer.Write(record); err != nil {
		return err
	}
	_, err := writer.Write(packet)
	return err
}

func (c *pcapCapture) Close() error {
	c.closeOnce.Do(func() {
		c.stateMu.Lock()
		c.closed = true
		close(c.events)
		c.stateMu.Unlock()
	})
	<-c.done
	return c.writeErr
}

type pcapConn struct {
	net.Conn
	capture *pcapCapture
	connID  uint32
	local   *net.TCPAddr
	remote  *net.TCPAddr

	readMu  sync.Mutex
	writeMu sync.Mutex
}

func (c *pcapConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.capturePayload(captureIncoming, p[:n], time.Now())
	}
	return n, err
}

func (c *pcapConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.capturePayload(captureOutgoing, p[:n], time.Now())
	}
	return n, err
}

func (c *pcapConn) capturePayload(direction captureDirection, payload []byte, timestamp time.Time) {
	for len(payload) > 0 {
		chunkSize := min(len(payload), maxTCPPayload)
		event := captureEvent{
			connID:    c.connID,
			direction: direction,
			timestamp: timestamp,
			local:     c.local,
			remote:    c.remote,
			payload:   append([]byte(nil), payload[:chunkSize]...),
		}
		if err := c.capture.enqueue(event); err != nil {
			return
		}
		payload = payload[chunkSize:]
	}
}

type pcapStreamState struct {
	sendSeq    uint32
	receiveSeq uint32
}

func (s *pcapStreamState) packet(event captureEvent) ([]byte, error) {
	var src, dst *net.TCPAddr
	var seq, ack uint32
	if event.direction == captureOutgoing {
		src, dst = event.local, event.remote
		seq, ack = s.sendSeq, s.receiveSeq
		s.sendSeq += uint32(len(event.payload))
	} else {
		src, dst = event.remote, event.local
		seq, ack = s.receiveSeq, s.sendSeq
		s.receiveSeq += uint32(len(event.payload))
	}
	return serializeTCPPacket(src, dst, seq, ack, event.payload)
}

func serializeTCPPacket(src, dst *net.TCPAddr, seq, ack uint32, payload []byte) ([]byte, error) {
	src4, dst4 := src.IP.To4(), dst.IP.To4()
	if src4 != nil && dst4 != nil {
		return serializeIPv4TCP(src4, dst4, src.Port, dst.Port, seq, ack, payload), nil
	}
	src6, dst6 := src.IP.To16(), dst.IP.To16()
	if src6 == nil || dst6 == nil || src4 != nil || dst4 != nil {
		return nil, fmt.Errorf("incompatible TCP address families: %s and %s", src, dst)
	}
	return serializeIPv6TCP(src6, dst6, src.Port, dst.Port, seq, ack, payload), nil
}

func serializeIPv4TCP(src, dst net.IP, srcPort, dstPort int, seq, ack uint32, payload []byte) []byte {
	packet := make([]byte, 20+20+len(payload))
	ip := packet[:20]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(packet)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))

	tcp := packet[20:40]
	writeTCPHeader(tcp, srcPort, dstPort, seq, ack)
	copy(packet[40:], payload)
	pseudo := make([]byte, 12+len(packet)-20)
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(packet)-20))
	copy(pseudo[12:], packet[20:])
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))
	return packet
}

func serializeIPv6TCP(src, dst net.IP, srcPort, dstPort int, seq, ack uint32, payload []byte) []byte {
	packet := make([]byte, 40+20+len(payload))
	ip := packet[:40]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(packet)-40))
	ip[6] = 6
	ip[7] = 64
	copy(ip[8:24], src)
	copy(ip[24:40], dst)

	tcp := packet[40:60]
	writeTCPHeader(tcp, srcPort, dstPort, seq, ack)
	copy(packet[60:], payload)
	pseudo := make([]byte, 40+len(packet)-40)
	copy(pseudo[0:16], src)
	copy(pseudo[16:32], dst)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(packet)-40))
	pseudo[39] = 6
	copy(pseudo[40:], packet[40:])
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))
	return packet
}

func writeTCPHeader(header []byte, srcPort, dstPort int, seq, ack uint32) {
	binary.BigEndian.PutUint16(header[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(header[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(header[4:8], seq)
	binary.BigEndian.PutUint32(header[8:12], ack)
	header[12] = 5 << 4
	header[13] = 0x18 // PSH + ACK
	binary.BigEndian.PutUint16(header[14:16], 65_535)
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
