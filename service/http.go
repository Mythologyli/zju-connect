package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
)

const (
	httpProxyMaxIdleConns        = 100
	httpProxyMaxIdleConnsPerHost = 10
	httpProxyMaxConnsPerHost     = 50
	httpProxyIdleConnTimeout     = 90 * time.Second
	httpProxyResponseTimeout     = 30 * time.Second
	httpProxyReadHeaderTimeout   = 10 * time.Second
	httpProxyServerIdleTimeout   = 90 * time.Second
)

// The MIT License (MIT)
//
// Copyright (c) 2016 Ian Denhardt <ian@zenhack.net>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

type httpTunnel struct {
	client net.Conn
	target net.Conn
}

type httpProxy struct {
	dialContext func(context.Context, string, string) (net.Conn, error)
	client      *http.Client
	tunnelsMu   sync.Mutex
	tunnels     map[*httpTunnel]struct{}
}

func newHTTPProxy(dialer *dial.Dialer) *httpProxy {
	proxy := &httpProxy{
		dialContext: dialer.Dial,
		tunnels:     make(map[*httpTunnel]struct{}),
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, net, addr string) (net.Conn, error) {
		return proxy.dialContext(ctx, net, addr)
	}
	transport.MaxIdleConns = httpProxyMaxIdleConns
	transport.MaxIdleConnsPerHost = httpProxyMaxIdleConnsPerHost
	transport.MaxConnsPerHost = httpProxyMaxConnsPerHost
	transport.IdleConnTimeout = httpProxyIdleConnTimeout
	transport.ResponseHeaderTimeout = httpProxyResponseTimeout
	proxy.client = &http.Client{
		Transport: transport,
		// We must pass redirect response to browser
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return proxy
}

func newHTTPHandler(dialer *dial.Dialer) http.Handler {
	return newHTTPProxy(dialer)
}

func (p *httpProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		p.handleConnect(w, req)
		return
	}

	log.DebugPrintf("HTTP proxy request: %s %s", req.Method, req.URL.String())
	req.RequestURI = ""

	resp, err := p.client.Do(req)
	if err != nil {
		log.DebugPrintf("HTTP proxy upstream request failed: %s %s: %v", req.Method, req.URL.String(), err)
		w.WriteHeader(500)
		_, _ = w.Write([]byte(err.Error() + "\n"))
		return
	}
	defer resp.Body.Close()
	log.DebugPrintf("HTTP proxy upstream response: %s %s: %s", req.Method, req.URL.String(), resp.Status)

	hdr := w.Header()
	for k, v := range resp.Header {
		hdr[k] = v
	}

	w.WriteHeader(resp.StatusCode)

	written, err := io.Copy(w, resp.Body)
	if err != nil {
		log.DebugPrintf("HTTP proxy response relay failed after %d bytes: %s %s: %v", written, req.Method, req.URL.String(), err)
		return
	}
	log.DebugPrintf("HTTP proxy response relayed: %s %s: %d bytes", req.Method, req.URL.String(), written)
}

func (p *httpProxy) handleConnect(w http.ResponseWriter, req *http.Request) {
	log.DebugPrintf("HTTP proxy CONNECT request: %s", req.Host)
	targetConn, err := p.dialContext(req.Context(), "tcp", req.Host)
	if err != nil {
		log.DebugPrintf("HTTP proxy CONNECT dial failed: %s: %v", req.Host, err)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error() + "\n"))
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = targetConn.Close()
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Failed cast to hijacker\n"))
		return
	}

	clientConn, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = targetConn.Close()
		return
	}

	tunnel := &httpTunnel{client: clientConn, target: targetConn}
	p.registerTunnel(tunnel)
	defer p.unregisterTunnel(tunnel)
	defer clientConn.Close()
	defer targetConn.Close()

	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		log.DebugPrintf("HTTP proxy CONNECT response failed: %s: %v", req.Host, err)
		return
	}
	log.DebugPrintf("HTTP proxy CONNECT established: %s", req.Host)

	relayDone := make(chan struct{}, 2)
	go relayHTTPConnect(targetConn, buffered, req.Host, "upstream", relayDone)
	go relayHTTPConnect(clientConn, targetConn, req.Host, "downstream", relayDone)
	<-relayDone
	_ = clientConn.Close()
	_ = targetConn.Close()
	<-relayDone
}

func relayHTTPConnect(dst net.Conn, src io.Reader, host, direction string, done chan<- struct{}) {
	written, err := io.Copy(dst, src)
	log.DebugPrintf("HTTP proxy CONNECT %s relay ended: %s: %d bytes: %v", direction, host, written, err)
	if conn, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = conn.CloseWrite()
	}
	if conn, ok := src.(interface{ CloseRead() error }); ok {
		_ = conn.CloseRead()
	}
	done <- struct{}{}
}

func (p *httpProxy) registerTunnel(tunnel *httpTunnel) {
	p.tunnelsMu.Lock()
	p.tunnels[tunnel] = struct{}{}
	p.tunnelsMu.Unlock()
}

func (p *httpProxy) unregisterTunnel(tunnel *httpTunnel) {
	p.tunnelsMu.Lock()
	delete(p.tunnels, tunnel)
	p.tunnelsMu.Unlock()
}

func (p *httpProxy) closeTunnels() {
	p.tunnelsMu.Lock()
	tunnels := make([]*httpTunnel, 0, len(p.tunnels))
	for tunnel := range p.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	p.tunnelsMu.Unlock()

	for _, tunnel := range tunnels {
		_ = tunnel.client.Close()
		_ = tunnel.target.Close()
	}
}

func (p *httpProxy) close() {
	p.closeTunnels()
	p.client.CloseIdleConnections()
}

func newHTTPServer(bindAddr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              bindAddr,
		Handler:           handler,
		ReadHeaderTimeout: httpProxyReadHeaderTimeout,
		IdleTimeout:       httpProxyServerIdleTimeout,
	}
}

func ServeHTTP(bindAddr string, dialer *dial.Dialer) {
	proxy := newHTTPProxy(dialer)

	log.Printf("HTTP server listening on %s", bindAddr)

	server := newHTTPServer(bindAddr, proxy)

	hook_func.RegisterTerminalFunc("CloseHTTPListener", func(ctx context.Context) error {
		log.Println("Closing HTTP listener...")
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		defer proxy.close()
		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("close HTTP listener failed: %w", err)
		}
		return nil
	})

	if err := server.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			log.Println("HTTP server closed")
		} else {
			log.Println("HTTP listen failed: " + err.Error())
		}
	}
}
