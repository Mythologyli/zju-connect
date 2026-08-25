package easyconnect

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/client/authchallenge"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"inet.af/netaddr"
)

const (
	easyConnectHTTPTimeout           = 30 * time.Second
	easyConnectDialTimeout           = 10 * time.Second
	easyConnectResponseHeaderTimeout = 15 * time.Second
	easyConnectRawRequestTimeout     = 15 * time.Second
)

type AuthOptions struct {
	Username      string
	Password      string
	TOTPSecret    string
	Certificate   tls.Certificate
	GraphCodeFile string
}

type ResourceOptions struct {
	Fetch          bool
	IncludeDomains bool
}

type Options struct {
	Server           string
	Auth             AuthOptions
	SessionID        string
	TestMultiLine    bool
	Resources        ResourceOptions
	UnderlayDialer   client.UnderlayDialer
	TLSKeyLogWriter  io.Writer
	ChallengeHandler authchallenge.Handler
}

type Client struct {
	server            string // Example: rvpn.zju.edu.cn:443. No protocol prefix
	username          string
	password          string
	totpSecret        string
	tlsCert           tls.Certificate
	testMultiLine     bool
	parseResource     bool
	useDomainResource bool

	httpClient        *http.Client
	underlayDialer    client.UnderlayDialer
	tlsKeyLogWriter   io.Writer
	rawRequestTimeout time.Duration

	twfID string
	token *[48]byte

	lineList []string

	ipResources     []client.IPResource
	domainResources client.DomainResources
	ipSet           *netaddr.IPSet
	dnsResource     map[string][]net.IP
	dnsServer       string
	dnsServers      []string

	ip        net.IP // Client IP
	ipReverse []byte

	lifecycleCtx       context.Context
	lifecycleCancel    context.CancelFunc
	requestIPConn      net.Conn
	requestIPConnMu    sync.Mutex
	requestIPKeepAlive sync.Once
	keepAliveStarted   sync.Once
	closeOnce          sync.Once
	graphCodeFile      string
	challengeHandler   authchallenge.Handler
}

func NewClient(options Options) *Client {
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	challengeHandler := options.ChallengeHandler
	if challengeHandler == nil {
		challengeHandler = authchallenge.NewCLIHandler(authchallenge.CLIOptions{})
	}
	c := &Client{
		server:            options.Server,
		username:          options.Auth.Username,
		password:          options.Auth.Password,
		totpSecret:        options.Auth.TOTPSecret,
		tlsCert:           options.Auth.Certificate,
		testMultiLine:     options.TestMultiLine,
		parseResource:     options.Resources.Fetch,
		useDomainResource: options.Resources.IncludeDomains,
		httpClient:        &http.Client{Timeout: easyConnectHTTPTimeout},
		underlayDialer:    options.UnderlayDialer,
		tlsKeyLogWriter:   options.TLSKeyLogWriter,
		rawRequestTimeout: easyConnectRawRequestTimeout,
		twfID:             options.SessionID,
		lifecycleCtx:      lifecycleCtx,
		lifecycleCancel:   lifecycleCancel,
		graphCodeFile:     options.Auth.GraphCodeFile,
		challengeHandler:  challengeHandler,
	}
	c.setHTTPTransport(&tls.Config{InsecureSkipVerify: true})
	return c
}

// Close releases background resources held by the client. Safe to call
// multiple times.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		c.lifecycleCancel()
		c.httpClient.CloseIdleConnections()
		c.requestIPConnMu.Lock()
		if c.requestIPConn != nil {
			_ = c.requestIPConn.Close()
			c.requestIPConn = nil
		}
		c.requestIPConnMu.Unlock()
	})
}

func (c *Client) IP() (net.IP, error) {
	if c.ip == nil {
		return nil, errors.New("IP not available")
	}

	return c.ip.To4(), nil
}

func (c *Client) IPSet() (*netaddr.IPSet, error) {
	if c.ipSet == nil {
		return nil, errors.New("IP set not available")
	}

	return c.ipSet, nil
}

func (c *Client) IPResources() ([]client.IPResource, error) {
	if c.ipResources == nil {
		return nil, errors.New("IP resources not available")
	}

	return c.ipResources, nil
}

func (c *Client) DomainResources() (client.DomainResources, error) {
	if c.domainResources == nil {
		return nil, errors.New("domain resources not available")
	}

	return c.domainResources, nil
}

func (c *Client) DNSResource() (map[string][]net.IP, error) {
	if c.dnsResource == nil {
		return nil, errors.New("DNS resource not available")
	}

	return c.dnsResource, nil
}

func (c *Client) DNSServer() (string, error) {
	if c.dnsServer == "" {
		return "", errors.New("DNS server not available")
	}

	return c.dnsServer, nil
}

func (c *Client) DNSServers() ([]string, error) {
	if len(c.dnsServers) == 0 {
		return nil, errors.New("DNS servers not available")
	}
	return append([]string(nil), c.dnsServers...), nil
}

func (c *Client) CanUseTCPTunnel() bool {
	return false
}

func (c *Client) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	return nil, errors.New("not supported")
}

func (c *Client) Setup() error {
	if c.underlayDialer == nil {
		return errors.New("underlay dialer is required")
	}
	if err := c.ensureSession(); err != nil {
		return err
	}

	// Probe at most once. If the selected line changes, establish one fresh
	// session on that line before continuing setup.
	if c.testMultiLine {
		configStr, err := c.requestConfig()
		if err != nil {
			log.Printf("Error occurred while requesting config: %v", err)
		} else if err := c.parseLineListFromConfig(configStr); err != nil {
			log.Printf("Error occurred while parsing config: %v", err)
		} else {
			log.Printf("Line list: %v", c.lineList)

			bestLine, err := findBestLine(c.lineList, c.dialContext, c.tlsKeyLogWriter)
			if err != nil {
				log.Printf("Error occurred while finding best line: %v", err)
			} else {
				log.Printf("Best line: %v", bestLine)
				if c.server != bestLine {
					c.server = bestLine
					c.testMultiLine = false
					c.twfID = ""
					if err := c.ensureSession(); err != nil {
						return err
					}
				}
			}
		}
	}

	// Then, use the TwfID to get token
	err := c.requestToken()
	if err != nil {
		return err
	}

	startTime := time.Now()

	// Then we get the resources from server
	if c.parseResource {
		resources, err := c.requestResources()
		if err != nil {
			log.Printf("Error occurred while requesting resources: %v", err)
		} else {
			// Parse the resources
			err = c.parseResources(resources)
			if err != nil {
				log.Printf("Error occurred while parsing resources: %v", err)
			}
		}
	}

	// Error may occur if we request too fast
	if time.Since(startTime) < time.Second {
		time.Sleep(time.Second - time.Since(startTime))
	}

	// Finally, use the token to get client IP
	err = c.requestIP()
	if err != nil {
		return err
	}

	// Periodic session keepalive. Without this, sangfor servers with strict
	// idle policies (observed at HUST) close the session as idle, which
	// surfaces as "broken pipe" + "unexpected handshake reply" panics in
	// the L3 tunnel layer. The official EasyConnect client calls
	// /por/update_session.csp; we mirror that. Guarded by sync.Once so the
	// repeated Setup calls don't double-start it.
	c.keepAliveStarted.Do(func() {
		hook_func.RegisterTerminalFunc("CloseSessionKeepAlive", func(ctx context.Context) error {
			c.Close()
			return nil
		})
		go c.sessionKeepAliveLoop()
	})

	return nil
}

func (c *Client) ensureSession() error {
	if c.twfID != "" {
		return nil
	}
	return c.requestTwfID(c.graphCodeFile)
}

func (c *Client) setHTTPTransport(tlsConfig *tls.Config) {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = c.dialContext
	transport.TLSClientConfig = tlsConfig.Clone()
	if c.tlsKeyLogWriter != nil {
		transport.TLSClientConfig.KeyLogWriter = c.tlsKeyLogWriter
	}
	transport.ResponseHeaderTimeout = easyConnectResponseHeaderTimeout
	c.httpClient.Transport = transport
}

func (c *Client) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c.underlayDialer == nil {
		return (&net.Dialer{Timeout: easyConnectDialTimeout, KeepAlive: 30 * time.Second}).DialContext(ctx, network, address)
	}
	return c.underlayDialer.DialContext(ctx, network, address)
}

func (c *Client) rawRequestContext() (context.Context, context.CancelFunc) {
	timeout := c.rawRequestTimeout
	if timeout <= 0 {
		timeout = easyConnectRawRequestTimeout
	}
	return context.WithTimeout(c.lifecycleCtx, timeout)
}

func armConnectionContext(ctx context.Context, conn net.Conn) (func(), error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	return func() {
		stopCancel()
		_ = conn.SetDeadline(time.Time{})
	}, nil
}

func (c *Client) sessionKeepAliveLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	c.runSessionKeepAlive(ticker.C, 10*time.Second)
}

func (c *Client) runSessionKeepAlive(ticks <-chan time.Time, requestTimeout time.Duration) {
	for {
		select {
		case <-c.lifecycleCtx.Done():
			return
		case <-ticks:
			ctx, cancel := context.WithTimeout(c.lifecycleCtx, requestTimeout)
			err := c.requestUpdateSession(ctx)
			cancel()
			if err != nil {
				if err == errNotFound {
					log.Println("server does not support update_session, stopping keepalive")
					return
				}
				log.Printf("update_session keepalive failed: %v", err)
			}
		}
	}
}
