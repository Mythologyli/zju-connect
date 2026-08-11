package atrust

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mythologyli/zju-connect/internal/zctcpip"
	"github.com/mythologyli/zju-connect/log"
)

const (
	l3Version        = 0x05
	cmdAuthReq       = 0x13
	cmdAuthResp      = 0x93
	cmdDataReq       = 0x14
	cmdDataResp      = 0x94
	cmdHeartbeatReq  = 0x15
	cmdHeartbeatResp = 0x95
	cmdSecondVipResp = 0x96

	defaultHeartbeatInterval  = 10 * time.Second
	defaultHeartbeatMissLimit = 3
	defaultAuthTimeout        = 8 * time.Second
	defaultAuthScanInterval   = 250 * time.Millisecond
	defaultAuthRetryWait      = time.Second
	defaultAuthMaxAttempts    = 3
	defaultAuthBatchSize      = 64
)

var errL3TunnelAuthTimeout = errors.New("l3-tunnel auth timeout")

type dataFrame struct {
	payload []byte
}

var dataFramePool = sync.Pool{
	New: func() any {
		return &dataFrame{payload: make([]byte, 0, 2048)}
	},
}

type clientInfo struct {
	sid          string
	deviceID     string
	connectionID string
	username     string
}

type l3TunnelConn struct {
	addr               string
	tlsConn            *tls.Conn
	reader             *bufio.Reader
	writeMu            sync.Mutex
	incoming           chan []byte
	closeOnce          sync.Once
	closeCh            chan struct{}
	conntrackMgr       *conntrackMgr
	signKey            []byte
	info               clientInfo
	onVIP              func([]net.IP)
	heartbeatInterval  time.Duration
	heartbeatMissLimit int32
	heartbeatMisses    int32
	authWake           chan struct{}
	writeFrameHook     func([]byte) error
	dataStream         []byte
}

type authIP struct {
	Atype    int    `json:"atype"`
	Protocol int    `json:"protocol"`
	DestAddr string `json:"destAddr"`
	DestPort uint16 `json:"destPort"`
	SrcAddr  string `json:"srcAddr"`
	SrcPort  uint16 `json:"srcPort"`
}

type authRequestIP struct {
	Sid           string    `json:"sid"`
	AppID         string    `json:"appId"`
	URL           string    `json:"url"`
	DeviceID      string    `json:"deviceId"`
	ConnectionID  string    `json:"connectionId"`
	Env           *trustEnv `json:"env,omitempty"`
	ConntrackHash uint64    `json:"conntrackHash"`
	Lang          string    `json:"lang"`
	IP            authIP    `json:"ip"`
	Domain        string    `json:"domain,omitempty"`
	ProcHash      string    `json:"procHash,omitempty"`
	XRequestSig   string    `json:"xRequestSig"`
}

type authResponseIP struct {
	Code    int64              `json:"code"`
	Message string             `json:"message"`
	Data    authResponseIPData `json:"data"`
}

type authResponseIPData struct {
	VipType       string `json:"vipType,omitempty"`
	Vip6Type      string `json:"vip6Type,omitempty"`
	Vip4Type      string `json:"vip4Type,omitempty"`
	ConntrackHash uint64 `json:"conntrackHash"`
	ConnectToken  string `json:"connectToken,omitempty"`
	Token         string `json:"token,omitempty"`
	IP            authIP `json:"ip"`
}

type authRequestSID struct {
	Sid string `json:"sid"`
}

type authResponseSID struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
	Data    struct {
		DeviceID string `json:"deviceId"`
	} `json:"data"`
}

type trustEnv struct {
	Application struct {
		Runtime struct {
			Process struct {
				Name             string `json:"name"`
				DigitalSignature string `json:"digital_signature"`
				Platform         string `json:"platform"`
				Fingerprint      string `json:"fingerprint"`
				Description      string `json:"description"`
				Path             string `json:"path"`
				Version          string `json:"version"`
				SecurityEnv      string `json:"security_env"`
			} `json:"process"`
			ProcessTrusted string `json:"process_trusted"`
		} `json:"runtime"`
	} `json:"application"`
}

type packetMeta struct {
	atype   int
	proto   int
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	key     string
}

type frame struct {
	cmd     byte
	status  byte
	payload []byte
}

func newL3TunnelConn(ctx context.Context, dialTLS func(context.Context, string, string, *tls.Config) (*tls.Conn, error), addr string, info clientInfo, signKeyHex string, onVIP func([]net.IP)) (*l3TunnelConn, error) {
	tlsConn, err := dialTLS(ctx, "tcp", addr, tunnelTLSConfig())
	if err != nil {
		return nil, err
	}

	signKey, err := hex.DecodeString(signKeyHex)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("invalid sign key: %w", err)
	}

	c := &l3TunnelConn{
		addr:               addr,
		tlsConn:            tlsConn,
		reader:             bufio.NewReader(tlsConn),
		incoming:           make(chan []byte, 128),
		closeCh:            make(chan struct{}),
		conntrackMgr:       newConntrackMgr(),
		signKey:            signKey,
		info:               info,
		onVIP:              onVIP,
		heartbeatInterval:  defaultHeartbeatInterval,
		heartbeatMissLimit: defaultHeartbeatMissLimit,
		authWake:           make(chan struct{}, 1),
	}
	if err := c.withContextDeadline(ctx, c.authTunnel); err != nil {
		_ = c.Close()
		return nil, err
	}

	go c.authLoop()
	go c.readLoop()
	go c.heartbeatLoop()
	return c, nil
}

func (c *l3TunnelConn) withContextDeadline(ctx context.Context, operation func() error) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return operation()
	}
	if err := c.tlsConn.SetDeadline(deadline); err != nil {
		return err
	}
	operationErr := operation()
	clearErr := c.tlsConn.SetDeadline(time.Time{})
	if operationErr != nil {
		return operationErr
	}
	return clearErr
}

func (c *l3TunnelConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closeCh)
		c.conntrackMgr.close()
		err = c.tlsConn.Close()
	})
	return err
}

func (c *l3TunnelConn) readLoop() {
	for {
		fr, err := c.readFrame()
		if err != nil {
			log.DebugPrintf("l3-tunnel read frame failed: %v", err)
			_ = c.Close()
			return
		}

		switch fr.cmd {
		case cmdDataResp:
			c.dataStream = append(c.dataStream, fr.payload...)
			packets, remaining, err := splitIncomingIPPackets(c.dataStream)
			if err != nil {
				log.DebugPrintf("l3-tunnel parse data stream failed: %v", err)
				_ = c.Close()
				return
			}
			c.dataStream = remaining
			if log.DebugEnabled() {
				log.DebugPrintf("l3-tunnel recv data packets=%d payloadLen=%d buffered=%d", len(packets), len(fr.payload), len(remaining))
			}
			for _, pkt := range packets {
				c.refreshIncomingConntrack(pkt)
				if !c.deliverIncoming(pkt) {
					return
				}
			}
		case cmdAuthResp:
			log.DebugPrintf("l3-tunnel recv auth resp status=%d payloadLen=%d", fr.status, len(fr.payload))
			c.handleAuthResp(fr.status, fr.payload)
		case cmdSecondVipResp:
			log.DebugPrintf("l3-tunnel recv vip update cmd=0x%02x status=%d payloadLen=%d", fr.cmd, fr.status, len(fr.payload))
			c.handleSecondVipResp(fr.status, fr.payload)
		case cmdHeartbeatResp:
			log.DebugPrintf("l3-tunnel recv heartbeat")
			atomic.StoreInt32(&c.heartbeatMisses, 0)
		default:
			log.DebugPrintf("l3-tunnel ignore cmd 0x%02x", fr.cmd)
		}
	}
}

func (c *l3TunnelConn) refreshIncomingConntrack(packet []byte) {
	ipPacket := zctcpip.IPv4Packet(packet)
	if !ipPacket.Valid() {
		return
	}
	meta, err := buildPacketMeta(ipPacket)
	if err != nil {
		return
	}
	meta.srcIP, meta.dstIP = meta.dstIP, meta.srcIP
	meta.srcPort, meta.dstPort = meta.dstPort, meta.srcPort
	c.conntrackMgr.touch(connTrackKey(meta))
}

func (c *l3TunnelConn) deliverIncoming(packet []byte) bool {
	select {
	case c.incoming <- packet:
		return true
	case <-c.closeCh:
		return false
	}
}

func (c *l3TunnelConn) heartbeatLoop() {
	interval := c.heartbeatInterval
	if interval <= 0 {
		interval = defaultHeartbeatInterval
	}
	missLimit := c.heartbeatMissLimit
	if missLimit <= 0 {
		missLimit = defaultHeartbeatMissLimit
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	if !c.sendHeartbeat() {
		return
	}
	for {
		select {
		case <-ticker.C:
			c.conntrackMgr.removeExpired()
			misses := atomic.LoadInt32(&c.heartbeatMisses)
			if misses >= missLimit {
				log.DebugPrintf("l3-tunnel heartbeat timed out after %d missed responses", misses)
				_ = c.Close()
				return
			}
			if !c.sendHeartbeat() {
				return
			}
		case <-c.closeCh:
			return
		}
	}
}

func (c *l3TunnelConn) sendHeartbeat() bool {
	atomic.AddInt32(&c.heartbeatMisses, 1)
	if err := c.writeFrame([]byte{l3Version, cmdHeartbeatReq, 0x00, 0x00}); err != nil {
		log.DebugPrintf("l3-tunnel heartbeat write failed: %v", err)
		_ = c.Close()
		return false
	}
	return true
}

func (c *l3TunnelConn) readFrame() (frame, error) {
	for {
		header := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, header); err != nil {
			return frame{}, err
		}
		if header[0] == l3Version {
			cmd := header[1]

			if cmd == cmdAuthResp || cmd == cmdSecondVipResp {
				statusLen := make([]byte, 3)
				if _, err := io.ReadFull(c.reader, statusLen); err != nil {
					return frame{}, err
				}
				status := statusLen[0]
				payloadLen := int(binary.BigEndian.Uint16(statusLen[1:3]))
				payload := make([]byte, payloadLen)
				if payloadLen > 0 {
					if _, err := io.ReadFull(c.reader, payload); err != nil {
						return frame{}, err
					}
				}
				if log.DebugEnabled() {
					raw := append(append(header, statusLen...), payload...)
					logFrame("recv", raw)
				}
				return frame{cmd: cmd, status: status, payload: payload}, nil
			}
			if cmd == cmdDataResp {
				payload, err := readDataRespPayload(c.reader)
				if err != nil {
					return frame{}, err
				}
				if log.DebugEnabled() {
					lenBytes := make([]byte, 2)
					binary.BigEndian.PutUint16(lenBytes, uint16(len(payload)))
					raw := append(append(append([]byte{}, header...), lenBytes...), payload...)
					logFrame("recv", raw)
					log.DebugPrintf("l3-tunnel recv data resp payloadLen=%d", len(payload))
				}
				return frame{cmd: cmd, payload: payload}, nil
			}

			lenBytes := make([]byte, 2)
			if _, err := io.ReadFull(c.reader, lenBytes); err != nil {
				return frame{}, err
			}
			payloadLen := int(binary.BigEndian.Uint16(lenBytes))
			payload := make([]byte, payloadLen)
			if payloadLen > 0 {
				if _, err := io.ReadFull(c.reader, payload); err != nil {
					return frame{}, err
				}
			}
			if log.DebugEnabled() {
				raw := append(append(header, lenBytes...), payload...)
				logFrame("recv", raw)
			}
			return frame{cmd: cmd, payload: payload}, nil
		}

		if header[0] == 0x53 && header[1] == 0x00 {
			lenBytes := make([]byte, 2)
			if _, err := io.ReadFull(c.reader, lenBytes); err != nil {
				return frame{}, err
			}
			payloadLen := int(binary.BigEndian.Uint16(lenBytes))
			payload := make([]byte, payloadLen)
			if payloadLen > 0 {
				if _, err := io.ReadFull(c.reader, payload); err != nil {
					return frame{}, err
				}
			}
			if log.DebugEnabled() {
				raw := append(append(header, lenBytes...), payload...)
				logFrame("recv protocol", raw)
			}
			continue
		}

		logFrame("recv unknown", header)
		return frame{}, fmt.Errorf("unexpected header: 0x%02x 0x%02x", header[0], header[1])
	}
}

func (c *l3TunnelConn) ReadPacket() ([]byte, error) {
	select {
	case pkt := <-c.incoming:
		return pkt, nil
	case <-c.closeCh:
		return nil, io.EOF
	}
}

func (c *l3TunnelConn) WritePacket(meta packetMeta, appID, nodeGroupID string, pkt []byte) error {
	ct := c.conntrackMgr.getOrCreate(meta.key, appID, nodeGroupID)
	ct.sendMu.Lock()
	defer ct.sendMu.Unlock()

	token, authErr, authenticated := c.conntrackMgr.authResult(ct)
	if authenticated {
		if authErr != nil {
			return authErr
		}
		return c.writeAuthenticatedPacket(ct, meta, appID, nodeGroupID, token, pkt)
	}

	_, err := c.conntrackMgr.cachePacket(ct, meta, pkt)
	if errors.Is(err, errPendingPacketCacheFull) {
		log.DebugPrintf("l3-tunnel pending packet cache full for %s; dropping packet", ct.key)
		return nil
	}
	if err != nil {
		return err
	}
	c.notifyAuth()
	return nil
}

func (c *l3TunnelConn) writeAuthenticatedPacket(ct *conntrack, meta packetMeta, appID, nodeGroupID, token string, pkt []byte) error {
	if token == "" {
		return fmt.Errorf("l3-tunnel missing connect token for %s", ct.key)
	}
	if len(token) > 0xFF {
		return fmt.Errorf("l3-tunnel connect token too long: %d", len(token))
	}
	frame := getDataPayload(token, pkt)
	defer putDataPayload(frame)
	payload := frame.payload
	if log.DebugEnabled() {
		log.DebugPrintf("l3-tunnel send data meta=%s appID=%s group=%s authID=%d tokenLen=%d pktLen=%d payloadLen=%d", formatMeta(meta), appID, nodeGroupID, ct.authID, len(token), len(pkt), len(payload))
	}
	err := c.writeFrame(payload)
	if err == nil && packetClosesConntrack(pkt) {
		c.conntrackMgr.remove(meta.key)
	}
	return err
}

func (c *l3TunnelConn) notifyAuth() {
	select {
	case c.authWake <- struct{}{}:
	default:
	}
}

func (c *l3TunnelConn) authLoop() {
	ticker := time.NewTicker(defaultAuthScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.authWake:
			if !c.dispatchPendingAuth() {
				return
			}
		case now := <-ticker.C:
			if expired := c.conntrackMgr.expireAuth(now, errL3TunnelAuthTimeout); expired > 0 {
				log.DebugPrintf("l3-tunnel exhausted retries for %d pending authentications", expired)
			}
			if !c.dispatchPendingAuth() {
				return
			}
		case <-c.closeCh:
			return
		}
	}
}

func (c *l3TunnelConn) dispatchPendingAuth() bool {
	for {
		jobs, more := c.conntrackMgr.nextAuthBatch(defaultAuthBatchSize)
		for _, job := range jobs {
			if err := c.sendAuthRequest(job.conntrack, job.meta); err != nil {
				c.conntrackMgr.markAuth(job.conntrack.authID, "", err)
				_ = c.Close()
				return false
			}
			c.conntrackMgr.markAuthSent(job.conntrack.authID, time.Now().Add(defaultAuthTimeout))
		}
		if !more {
			return true
		}
	}
}

func (c *l3TunnelConn) sendAuthRequest(ct *conntrack, meta packetMeta) error {
	req, err := buildAuthRequest(c.info, c.signKey, meta, ct)
	if err != nil {
		return err
	}
	if log.DebugEnabled() {
		log.DebugPrintf("l3-tunnel send auth authID=%d meta=%s payloadLen=%d", ct.authID, formatMeta(meta), len(req))
	}
	payload := make([]byte, 0, 4+len(req))
	payload = append(payload, l3Version, cmdAuthReq)
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(req)))
	payload = append(payload, lenBytes...)
	payload = append(payload, req...)
	return c.writeFrame(payload)
}

func (c *l3TunnelConn) handleAuthResp(status byte, payload []byte) {
	var resp authResponseIP
	if err := json.Unmarshal(payload, &resp); err != nil {
		c.markAuthErrorFromPayload(payload, err)
		return
	}
	if resp.Data.ConntrackHash == 0 {
		c.markAuthErrorFromPayload(payload, fmt.Errorf("missing conntrack hash"))
		return
	}
	if status != 0 {
		if isRetryableAuthResponse(resp) {
			c.scheduleAuthRetry(resp.Data.ConntrackHash, defaultAuthRetryWait)
			return
		}
		c.completeAuthentication(resp.Data.ConntrackHash, "", fmt.Errorf("auth status %d: %s", status, resp.Message))
		return
	}

	var err error
	if resp.Code != 0 {
		if isRetryableAuthResponse(resp) {
			c.scheduleAuthRetry(resp.Data.ConntrackHash, defaultAuthRetryWait)
			return
		}
		err = fmt.Errorf("auth failed: %d %s", resp.Code, resp.Message)
	}
	token := strings.TrimSpace(resp.Data.ConnectToken)
	if token == "" {
		token = strings.TrimSpace(resp.Data.Token)
	}
	if err == nil && token == "" {
		err = fmt.Errorf("missing connect token")
	}
	log.DebugPrintf("l3-tunnel auth resp code=%d conntrack=%d tokenLen=%d", resp.Code, resp.Data.ConntrackHash, len(token))
	c.completeAuthentication(resp.Data.ConntrackHash, token, err)
}

func isRetryableAuthResponse(resp authResponseIP) bool {
	message := strings.ToLower(resp.Message)
	return strings.Contains(message, "busy") || strings.Contains(message, "try again") || strings.Contains(message, "稍后")
}

func (c *l3TunnelConn) scheduleAuthRetry(authID uint64, delay time.Duration) {
	if c.conntrackMgr.retryAuth(authID, delay) {
		log.DebugPrintf("l3-tunnel auth retry scheduled authID=%d delay=%s", authID, delay)
		c.notifyAuth()
	}
}

func (c *l3TunnelConn) handleSecondVipResp(status byte, payload []byte) {
	if status != 0 {
		log.DebugPrintf("l3-tunnel second vip status %d", status)
		return
	}
	ips := extractVIPs(payload)
	if len(ips) == 0 {
		return
	}
	if c.onVIP != nil {
		c.onVIP(ips)
	}
}

func (c *l3TunnelConn) markAuthErrorFromPayload(payload []byte, err error) {
	var resp authResponseIP
	if json.Unmarshal(payload, &resp) == nil && resp.Data.ConntrackHash != 0 {
		c.completeAuthentication(resp.Data.ConntrackHash, "", err)
	}
}

func (c *l3TunnelConn) completeAuthentication(authID uint64, token string, authErr error) {
	ct := c.conntrackMgr.getByID(authID)
	if ct == nil {
		return
	}
	ct.sendMu.Lock()
	defer ct.sendMu.Unlock()
	_, packets := c.conntrackMgr.completeAuth(authID, token, authErr)
	if authErr != nil {
		return
	}
	for _, packet := range packets {
		if err := c.writeAuthenticatedPacket(ct, ct.authMeta, ct.appID, ct.nodeGroupID, token, packet); err != nil {
			log.DebugPrintf("l3-tunnel flush authenticated packet failed: %v", err)
			_ = c.Close()
			return
		}
	}
}

func (c *l3TunnelConn) writeFrame(data []byte) error {
	if c.writeFrameHook != nil {
		return c.writeFrameHook(data)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	logFrame("send", data)
	n, err := c.tlsConn.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func (c *l3TunnelConn) writeRaw(label string, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	log.DebugPrintf("l3-tunnel %s len=%d", label, len(data))
	log.DebugDumpHex(data)
	_, err := c.tlsConn.Write(data)
	return err
}

func buildAuthRequest(info clientInfo, signKey []byte, meta packetMeta, ct *conntrack) ([]byte, error) {
	url := fmt.Sprintf("%s:%s:%d", protoName(meta.proto), meta.dstIP.String(), meta.dstPort)
	env := defaultEnv(info)

	req := authRequestIP{
		Sid:           info.sid,
		AppID:         ct.appID,
		URL:           url,
		DeviceID:      info.deviceID,
		ConnectionID:  info.connectionID,
		Env:           env,
		ConntrackHash: ct.authID,
		Lang:          langFromEnv(url),
		IP: authIP{
			Atype:    authIPType(meta.atype),
			Protocol: meta.proto,
			DestAddr: meta.dstIP.String(),
			DestPort: meta.dstPort,
			SrcAddr:  meta.srcIP.String(),
			SrcPort:  meta.srcPort,
		},
		ProcHash:    env.Application.Runtime.Process.Fingerprint,
		XRequestSig: "",
	}

	unsigned, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	sig := calcXRequestSig(signKey, unsigned)
	req.XRequestSig = sig
	return json.Marshal(req)
}

func defaultEnv(info clientInfo) *trustEnv {
	procPath := "/usr/bin/zju-connect"
	procName := "zju-connect"
	fingerprint := fmt.Sprintf("%X", sha256.Sum256([]byte(procPath)))
	platform := strings.Title(runtime.GOOS)
	if platform == "Darwin" {
		platform = "macOS"
	}

	var env trustEnv
	env.Application.Runtime.Process.Name = procName
	env.Application.Runtime.Process.DigitalSignature = "TrustAppClosed"
	env.Application.Runtime.Process.Platform = platform
	env.Application.Runtime.Process.Fingerprint = fingerprint
	env.Application.Runtime.Process.Description = "TrustAppClosed"
	env.Application.Runtime.Process.Path = procPath
	env.Application.Runtime.Process.Version = "TrustAppClosed"
	env.Application.Runtime.Process.SecurityEnv = "normal"
	env.Application.Runtime.ProcessTrusted = "TRUSTED"
	return &env
}

func encodeMeta(meta packetMeta) ([]byte, error) {
	srcIP := meta.srcIP.To4()
	dstIP := meta.dstIP.To4()
	if meta.atype == 4 && (srcIP == nil || dstIP == nil) {
		return nil, fmt.Errorf("invalid ipv4 addr")
	}

	buf := bytes.NewBuffer(nil)
	buf.WriteByte(byte(meta.atype))
	buf.WriteByte(byte(meta.proto))
	if meta.atype == 4 {
		buf.Write(srcIP)
		buf.Write(dstIP)
	} else {
		buf.Write(meta.srcIP.To16())
		buf.Write(meta.dstIP.To16())
	}
	_ = binary.Write(buf, binary.BigEndian, meta.srcPort)
	_ = binary.Write(buf, binary.BigEndian, meta.dstPort)
	return buf.Bytes(), nil
}

func getDataPayload(token string, packet []byte) *dataFrame {
	frame := dataFramePool.Get().(*dataFrame)
	payload := frame.payload[:0]
	required := 8 + len(token) + len(packet)
	if cap(payload) < required {
		payload = make([]byte, 0, required)
	}
	payload = append(payload, l3Version, cmdDataReq, byte(len(token)))
	payload = append(payload, token...)
	payload = append(payload, 0x00, 0x00, 0x01, 0x00, 0x00)
	binary.BigEndian.PutUint16(payload[len(payload)-2:], uint16(len(packet)))
	payload = append(payload, packet...)
	frame.payload = payload
	return frame
}

func putDataPayload(frame *dataFrame) {
	// Avoid retaining unexpectedly large packets in the process-wide pool.
	if cap(frame.payload) > maxPooledDataPayload {
		return
	}
	frame.payload = frame.payload[:0]
	dataFramePool.Put(frame)
}

const maxPooledDataPayload = 4096

func parseDataPayload(payload []byte) ([][]byte, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("payload too short")
	}
	tokenLen := int(payload[0])
	idx := 1 + tokenLen
	if len(payload) < idx+3 {
		return nil, fmt.Errorf("payload token overflow")
	}
	idx += 2 // reserved
	count := int(payload[idx])
	idx++

	packets := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		if idx+2 > len(payload) {
			return nil, fmt.Errorf("packet length overflow")
		}
		plen := int(binary.BigEndian.Uint16(payload[idx : idx+2]))
		idx += 2
		if idx+plen > len(payload) {
			return nil, fmt.Errorf("packet data overflow")
		}
		pkt := make([]byte, plen)
		copy(pkt, payload[idx:idx+plen])
		idx += plen
		packets = append(packets, pkt)
	}
	return packets, nil
}

func readDataRespPayload(r *bufio.Reader) ([]byte, error) {
	var lenBytes [2]byte
	if _, err := io.ReadFull(r, lenBytes[:]); err != nil {
		return nil, err
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(lenBytes[:])))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

const maxIncomingIPPacketSize = 1500

func splitIncomingIPPackets(stream []byte) ([][]byte, []byte, error) {
	var packets [][]byte
	for len(stream) > 0 {
		var packetLen int
		switch stream[0] >> 4 {
		case zctcpip.IPv4Version:
			if len(stream) < 4 {
				return packets, stream, nil
			}
			headerLen := int(stream[0]&0x0f) * 4
			packetLen = int(binary.BigEndian.Uint16(stream[2:4]))
			if headerLen < 20 || packetLen < headerLen {
				return nil, nil, fmt.Errorf("invalid IPv4 packet length %d with header length %d", packetLen, headerLen)
			}
		case 6:
			if len(stream) < 6 {
				return packets, stream, nil
			}
			packetLen = 40 + int(binary.BigEndian.Uint16(stream[4:6]))
		default:
			return nil, nil, fmt.Errorf("unexpected IP version %d", stream[0]>>4)
		}
		if packetLen > maxIncomingIPPacketSize {
			return nil, nil, fmt.Errorf("IP packet length %d exceeds %d", packetLen, maxIncomingIPPacketSize)
		}
		if len(stream) < packetLen {
			return packets, stream, nil
		}
		packet := append([]byte(nil), stream[:packetLen]...)
		packets = append(packets, packet)
		stream = stream[packetLen:]
	}
	return packets, nil, nil
}

func parseDataMeta(payload []byte) (packetMeta, int, error) {
	if len(payload) < 1 {
		return packetMeta{}, 0, fmt.Errorf("payload too short for meta")
	}
	metaLen := int(payload[0])
	if metaLen == 0 {
		return packetMeta{}, 0, fmt.Errorf("meta length is zero")
	}
	if len(payload) < 1+metaLen {
		return packetMeta{}, metaLen, fmt.Errorf("payload meta overflow")
	}
	metaBytes := payload[1 : 1+metaLen]
	meta, err := decodeMeta(metaBytes)
	return meta, metaLen, err
}

func decodeMeta(metaBytes []byte) (packetMeta, error) {
	if len(metaBytes) < 2 {
		return packetMeta{}, fmt.Errorf("meta too short")
	}
	meta := packetMeta{
		atype: int(metaBytes[0]),
		proto: int(metaBytes[1]),
	}
	offset := 2
	if meta.atype == 4 {
		if len(metaBytes) < offset+8+4 {
			return packetMeta{}, fmt.Errorf("meta ipv4 too short")
		}
		meta.srcIP = net.IPv4(metaBytes[offset], metaBytes[offset+1], metaBytes[offset+2], metaBytes[offset+3])
		offset += 4
		meta.dstIP = net.IPv4(metaBytes[offset], metaBytes[offset+1], metaBytes[offset+2], metaBytes[offset+3])
		offset += 4
	} else {
		if len(metaBytes) < offset+32+4 {
			return packetMeta{}, fmt.Errorf("meta ipv6 too short")
		}
		meta.srcIP = net.IP(metaBytes[offset : offset+16])
		offset += 16
		meta.dstIP = net.IP(metaBytes[offset : offset+16])
		offset += 16
	}
	meta.srcPort = binary.BigEndian.Uint16(metaBytes[offset : offset+2])
	offset += 2
	meta.dstPort = binary.BigEndian.Uint16(metaBytes[offset : offset+2])
	return meta, nil
}

func formatMeta(meta packetMeta) string {
	return fmt.Sprintf("atype=%d proto=%s %s:%d -> %s:%d", meta.atype, protoName(meta.proto), meta.srcIP, meta.srcPort, meta.dstIP, meta.dstPort)
}

func logFrame(prefix string, data []byte) {
	if !log.DebugEnabled() {
		return
	}
	if len(data) >= 2 {
		log.DebugPrintf("l3-tunnel %s frame cmd=0x%02x len=%d", prefix, data[1], len(data))
	} else {
		log.DebugPrintf("l3-tunnel %s frame len=%d", prefix, len(data))
	}
	log.DebugDumpHex(data)
}

func (c *l3TunnelConn) authTunnel() error {
	req, err := json.Marshal(authRequestSID{Sid: c.info.sid})
	if err != nil {
		return err
	}

	packet := wrapAuthReqData(req, 1)
	if err := c.writeRaw("send tunnel auth", packet); err != nil {
		return err
	}

	method := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, method); err != nil {
		return err
	}
	log.DebugPrintf("l3-tunnel recv tunnel auth method len=%d", len(method))
	log.DebugDumpHex(method)
	if method[0] != l3Version || method[1] != 0xD0 {
		return fmt.Errorf("l3-tunnel unexpected auth method resp: %02x %02x", method[0], method[1])
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return err
	}
	log.DebugPrintf("l3-tunnel recv tunnel auth header len=%d", len(header))
	log.DebugDumpHex(header)
	if header[0] != 0x53 {
		return fmt.Errorf("l3-tunnel unexpected auth resp version: 0x%02x", header[0])
	}
	status := header[1]
	length := int(binary.BigEndian.Uint16(header[2:4]))
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return err
		}
	}
	log.DebugPrintf("l3-tunnel recv tunnel auth payload len=%d status=%d", len(payload), status)
	log.DebugDumpHex(payload)
	if status != 0 {
		return fmt.Errorf("l3-tunnel tunnel auth status %d", status)
	}
	if len(payload) > 0 {
		var resp authResponseSID
		if err := json.Unmarshal(payload, &resp); err != nil {
			return err
		}
		if resp.Code != 0 {
			return fmt.Errorf("l3-tunnel tunnel auth failed: %d %s", resp.Code, resp.Message)
		}
	}

	vipHeader := make([]byte, 4)
	if _, err := io.ReadFull(c.reader, vipHeader); err != nil {
		return err
	}
	log.DebugPrintf("l3-tunnel recv tunnel vip header len=%d", len(vipHeader))
	log.DebugDumpHex(vipHeader)
	if vipHeader[0] != l3Version {
		return nil
	}

	addrType := vipHeader[3]
	dataLen := vipPayloadLength(addrType)
	if dataLen == 0 {
		return nil
	}
	vipData := make([]byte, dataLen)
	if _, err := io.ReadFull(c.reader, vipData); err != nil {
		return err
	}
	log.DebugPrintf("l3-tunnel recv tunnel vip data len=%d", len(vipData))
	log.DebugDumpHex(vipData)
	ips := parseVirtualIPData(vipData)
	if len(ips) > 0 && c.onVIP != nil {
		c.onVIP(ips)
	}
	return nil
}

func wrapAuthReqData(payload []byte, addrType byte) []byte {
	header := make([]byte, 4+len(payload))
	header[0] = 0x53
	header[1] = 0x00
	binary.BigEndian.PutUint16(header[2:4], uint16(len(payload)))
	copy(header[4:], payload)

	buf := make([]byte, 0, 3+len(header)+10)
	buf = append(buf, l3Version, 0x01, 0xD0)
	buf = append(buf, header...)
	buf = append(buf, 0x05, 0x04, 0x00, addrType, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	return buf
}

func vipPayloadLength(addrType byte) int {
	switch addrType {
	case 1:
		return 6
	case 4:
		return 18
	case 5:
		return 22
	default:
		return 4
	}
}

func parseVirtualIPData(data []byte) []net.IP {
	var ips []net.IP
	switch len(data) {
	case 6:
		ips = append(ips, net.IPv4(data[0], data[1], data[2], data[3]))
	case 18:
		ips = append(ips, net.IP(data[:16]))
	case 22:
		ips = append(ips, net.IPv4(data[0], data[1], data[2], data[3]))
		ips = append(ips, net.IP(data[4:20]))
	}
	return ips
}

func extractVIPs(payload []byte) []net.IP {
	type virtualIPs struct {
		VIP      string `json:"vip"`
		VIP6     string `json:"vip6"`
		VIPType  any    `json:"vip_type"`
		VIP6Type any    `json:"vip6_type"`
	}
	var resp struct {
		virtualIPs
		Data virtualIPs `json:"data"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil
	}
	values := resp.virtualIPs
	if values.VIP == "" && values.VIP6 == "" {
		values = resp.Data
	}
	ips := make([]net.IP, 0, 2)
	if ip := net.ParseIP(values.VIP); ip != nil && ip.To4() != nil {
		ips = append(ips, ip.To4())
	}
	if ip := net.ParseIP(values.VIP6); ip != nil && ip.To4() == nil {
		ips = append(ips, ip.To16())
	}
	return ips
}

func protoName(proto int) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmp6"
	default:
		return "ip"
	}
}

func authIPType(atype int) int {
	switch atype {
	case 6:
		return 0x86DD
	default:
		return 0x0800
	}
}

func langFromEnv(_ string) string {
	lang := firstNonEmpty(
		os.Getenv("ZJU_CONNECT_LANG"),
		os.Getenv("LC_ALL"),
		os.Getenv("LC_MESSAGES"),
		os.Getenv("LANG"),
	)
	if lang == "" {
		return "en-US"
	}
	lang = strings.Split(lang, ".")[0]
	lang = strings.ReplaceAll(lang, "_", "-")
	if len(lang) == 2 {
		lang = strings.ToLower(lang)
		return lang + "-" + strings.ToUpper(lang)
	}
	if parts := strings.Split(lang, "-"); len(parts) == 2 {
		return strings.ToLower(parts[0]) + "-" + strings.ToUpper(parts[1])
	}
	return lang
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func connTrackKey(meta packetMeta) string {
	return fmt.Sprintf("%d:%d:%s:%d-%s:%d", meta.atype, meta.proto, meta.srcIP.String(), meta.srcPort, meta.dstIP.String(), meta.dstPort)
}
