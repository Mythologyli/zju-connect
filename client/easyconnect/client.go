package easyconnect

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"inet.af/netaddr"
)

type Client struct {
	server            string // Example: rvpn.zju.edu.cn:443. No protocol prefix
	username          string
	password          string
	totpSecret        string
	tlsCert           tls.Certificate
	testMultiLine     bool
	parseResource     bool
	useDomainResource bool

	httpClient *http.Client

	twfID string
	token *[48]byte

	lineList []string

	ipResources     []client.IPResource
	domainResources map[string]client.DomainResource
	ipSet           *netaddr.IPSet
	dnsResource     map[string]net.IP
	dnsServer       string

	ip        net.IP // Client IP
	ipReverse []byte

	lifecycleCtx       context.Context
	lifecycleCancel    context.CancelFunc
	requestIPConn      net.Conn
	requestIPConnMu    sync.Mutex
	requestIPKeepAlive sync.Once
	keepAliveStarted   sync.Once
	closeOnce          sync.Once
}

func NewClient(server, username, password, totpSecret string, tlsCert tls.Certificate, twfID string, testMultiLine, parseResource, useDomainResource bool) *Client {
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	return &Client{
		server:            server,
		username:          username,
		password:          password,
		totpSecret:        totpSecret,
		tlsCert:           tlsCert,
		testMultiLine:     testMultiLine,
		parseResource:     parseResource,
		useDomainResource: useDomainResource,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}},
		twfID:           twfID,
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
	}
}

// Close releases background resources held by the client. Safe to call
// multiple times.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		c.lifecycleCancel()
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

func (c *Client) DomainResources() (map[string]client.DomainResource, error) {
	if c.domainResources == nil {
		return nil, errors.New("domain resources not available")
	}

	return c.domainResources, nil
}

func (c *Client) DNSResource() (map[string]net.IP, error) {
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

func (c *Client) CanUseTCPTunnel() bool {
	return false
}

func (c *Client) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	return nil, errors.New("not supported")
}

func (c *Client) Setup(graphCodeFile string) error {
	// Use username/password/(SMS code) to get the TwfID
	if c.twfID == "" {
		err := c.requestTwfID(graphCodeFile)
		if err != nil {
			return err
		}
	} // else we use the TwfID provided by user

	// Then we can get config from server and find the best line
	if c.testMultiLine {
		configStr, err := c.requestConfig()
		if err != nil {
			log.Printf("Error occurred while requesting config: %v", err)
		} else {
			err := c.parseLineListFromConfig(configStr)
			if err != nil {
				log.Printf("Error occurred while parsing config: %v", err)
			} else {
				log.Printf("Line list: %v", c.lineList)

				bestLine, err := findBestLine(c.lineList)
				if err != nil {
					log.Printf("Error occurred while finding best line: %v", err)
				} else {
					log.Printf("Best line: %v", bestLine)

					// Now we use the bestLine as new server
					if c.server != bestLine {
						c.server = bestLine
						c.testMultiLine = false
						c.twfID = ""

						return c.Setup(graphCodeFile)
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
	// recursive Setup() path (testMultiLine) doesn't double-start.
	c.keepAliveStarted.Do(func() {
		hook_func.RegisterTerminalFunc("CloseSessionKeepAlive", func(ctx context.Context) error {
			c.Close()
			return nil
		})
		go c.sessionKeepAliveLoop()
	})

	return nil
}

func (c *Client) sessionKeepAliveLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.lifecycleCtx.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(c.lifecycleCtx, 10*time.Second)
			cancel()
			if err := c.requestUpdateSession(ctx); err != nil {
				if err == errNotFound {
					log.Println("server does not support update_session, stopping keepalive")
					return
				}
				log.Printf("update_session keepalive failed: %v", err)
			}
		}
	}
}
