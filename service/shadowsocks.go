// The following code part comes from go-shadowsocks2
// Original code can be found at https://github.com/shadowsocks/go-shadowsocks2
// This code is covered by the Apache License 2.0. See https://github.com/shadowsocks/go-shadowsocks2/blob/master/LICENSE

package service

import (
	"context"
	"errors"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/log"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"time"
)

const udpBufSize = 64 * 1024
const udpTimeout = 5 * time.Minute

func parseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}

func ServeShadowsocks(dialer *dial.Dialer, url string) {
	addr, cipher, password, err := parseURL(url)
	if err != nil {
		panic(err)
	}

	ciph, err := core.PickCipher(cipher, []byte{}, password)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Shadowsocks server listening on %s", addr)

	go tcpRemote(addr, ciph.StreamConn, dialer)
	udpRemote(addr, ciph.PacketConn, dialer)
}

func tcpRemote(addr string, shadow func(net.Conn) net.Conn, dialer *dial.Dialer) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}

	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("failed to accept: %v", err)
			continue
		}

		go func() {
			defer c.Close()
			sc := shadow(c)

			tgt, err := socks.ReadAddr(sc)
			if err != nil {
				log.Printf("failed to get target address from %v: %v", c.RemoteAddr(), err)
				// drain c to avoid leaking server behavioral features
				// see https://www.ndss-symposium.org/ndss-paper/detecting-probe-resistant-proxies/
				_, err = io.Copy(io.Discard, c)
				if err != nil {
					log.Printf("discard error: %v", err)
				}
				return
			}

			rc, err := dialer.Dial(context.Background(), "tcp", tgt.String())
			if err != nil {
				log.Printf("failed to connect to target: %v", err)
				return
			}
			defer rc.Close()

			log.Printf("proxy %s <-> %s", c.RemoteAddr(), tgt)
			if err = relay(sc, rc); err != nil {
				log.Printf("relay error: %v", err)
			}
		}()
	}
}

// relay copies between left and right bidirectionally
func relay(left, right net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup
	var wait = 5 * time.Second
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err1 = io.Copy(right, left)
		_ = right.SetReadDeadline(time.Now().Add(wait)) // unblock read on right
	}()
	_, err = io.Copy(left, right)
	_ = left.SetReadDeadline(time.Now().Add(wait)) // unblock read on left
	wg.Wait()
	if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) { // requires Go 1.15+
		return err1
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return nil
}

// Listen on addr for encrypted packets and basically do UDP NAT.
func udpRemote(addr string, shadow func(net.PacketConn) net.PacketConn, dialer *dial.Dialer) {
	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Printf("UDP remote listen error: %v", err)
		return
	}
	defer func(c net.PacketConn) {
		_ = c.Close()
	}(c)
	c = shadow(c)

	nm := newNATMap(udpTimeout)
	buf := make([]byte, udpBufSize)

	log.Printf("listening UDP on %s", addr)
	for {
		n, raddr, err := c.ReadFrom(buf)
		if err != nil {
			log.Printf("UDP remote read error: %v", err)
			continue
		}

		targetAddr := socks.SplitAddr(buf[:n])
		if targetAddr == nil {
			log.Printf("failed to split target address from packet: %q", buf[:n])
			continue
		}

		payload := buf[len(targetAddr):n]

		targetConn := nm.Get(raddr.String())
		if targetConn == nil {
			targetConn, err = dialer.Dial(context.Background(), "udp", targetAddr.String())
			if err != nil {
				log.Printf("UDP remote listen error: %v", err)
				continue
			}

			nm.Add(raddr, targetConn)
			go func() {
				_ = udpServerToClientCopy(c, raddr, targetConn, nm.timeout)
				nm.Del(raddr.String())
				targetConn.Close()
			}()
		}

		_, err = targetConn.Write(payload) // accept only UDPAddr despite the signature
		if err != nil {
			log.Printf("UDP remote write error: %v", err)
			continue
		}
	}
}

// Packet NAT table
type udpNATMap struct {
	sync.RWMutex
	m       map[string]net.Conn
	timeout time.Duration
}

func newNATMap(timeout time.Duration) *udpNATMap {
	m := &udpNATMap{}
	m.m = make(map[string]net.Conn)
	m.timeout = timeout
	return m
}

func (m *udpNATMap) Get(key string) net.Conn {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *udpNATMap) Set(key string, targetConn net.Conn) {
	m.Lock()
	defer m.Unlock()

	m.m[key] = targetConn
}

func (m *udpNATMap) Del(key string) net.Conn {
	m.Lock()
	defer m.Unlock()

	targetConn, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return targetConn
	}
	return nil
}

func (m *udpNATMap) Add(peer net.Addr, targetConn net.Conn) {
	m.Set(peer.String(), targetConn)
}

func udpServerToClientCopy(c net.PacketConn, peer net.Addr, targetConn net.Conn, timeout time.Duration) error {
	buf := make([]byte, udpBufSize)

	for {
		_ = targetConn.SetReadDeadline(time.Now().Add(timeout))
		n, err := targetConn.Read(buf)
		if err != nil {
			return err
		}

		// server -> client: add original packet source
		srcAddr := socks.ParseAddr(targetConn.RemoteAddr().String())
		copy(buf[len(srcAddr):], buf[:n])
		copy(buf, srcAddr)
		_, err = c.WriteTo(buf[:len(srcAddr)+n], peer)

		if err != nil {
			return err
		}
	}
}
