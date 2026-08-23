package atrust

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/client/atrust/auth"
	"github.com/mythologyli/zju-connect/internal/ipresource"
	"github.com/mythologyli/zju-connect/internal/keylog"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/underlay"
	"inet.af/netaddr"
)

type Client struct {
	Username     string
	SID          string
	DeviceID     string
	ConnectionID string
	SignKey      string

	serverAddress   string
	ipResources     []client.IPResource
	resourceIndex   *ipresource.Index
	domainResources client.DomainResources
	ipSet           *netaddr.IPSet
	dnsResource     map[string][]net.IP
	dnsServer       string
	dnsServers      []string

	MajorNodeGroup   string
	NodeGroups       map[string]NodeGroup
	BestNodes        map[string]string
	BestNodesRWMutex sync.RWMutex

	ipMu sync.RWMutex
	ip   net.IP // Client IP

	ipUpdateMu      sync.RWMutex
	ipUpdateHandler func(net.IP) error

	l3Tunnel   *L3Tunnel
	l3TunnelMu sync.Mutex

	lifecycleCtx     context.Context
	lifecycleCancel  context.CancelFunc
	closeOnce        sync.Once
	underlayDialer   client.UnderlayDialer
	tlsKeyLogWriter  io.Writer
	tcpTunnelZeroRTT bool
}

func NewClient(username, sid, deviceID, signKey string, underlayDialer client.UnderlayDialer, tlsKeyLogWriter io.Writer) *Client {
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	return &Client{
		Username:        username,
		SID:             sid,
		DeviceID:        deviceID,
		SignKey:         signKey,
		underlayDialer:  underlayDialer,
		tlsKeyLogWriter: tlsKeyLogWriter,
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
	}
}

func (c *Client) Close() {
	c.closeOnce.Do(func() {
		c.lifecycleCancel()
		c.l3TunnelMu.Lock()
		tunnel := c.l3Tunnel
		c.l3TunnelMu.Unlock()
		if tunnel != nil {
			tunnel.Close()
		}
	})
}

func (c *Client) IP() (net.IP, error) {
	c.ipMu.RLock()
	defer c.ipMu.RUnlock()
	if c.ip == nil {
		return nil, errors.New("IP not available")
	}

	return append(net.IP(nil), c.ip.To4()...), nil
}

func (c *Client) setIP(ip net.IP) {
	c.ipMu.Lock()
	c.ip = append(net.IP(nil), ip...)
	c.ipMu.Unlock()
}

func (c *Client) SetIPUpdateHandler(handler func(net.IP) error) {
	c.ipUpdateMu.Lock()
	c.ipUpdateHandler = handler
	c.ipUpdateMu.Unlock()
}

func (c *Client) applyIPUpdate(ip net.IP) error {
	c.ipUpdateMu.RLock()
	handler := c.ipUpdateHandler
	c.ipUpdateMu.RUnlock()
	if handler == nil {
		return errors.New("network stack does not support virtual IP updates")
	}
	return handler(append(net.IP(nil), ip...))
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

func randHex(n int) string {
	numBytes := (n + 1) / 2
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strings.ToUpper(hex.EncodeToString(b)[:n])
}

func GetAuthInfoList(serverAddress string, serverPort int, bindInterface string, autoDetectInterface bool, localDNSServer, debugTLSLogFile string) (authInfo []auth.AuthInfo, err error) {
	var serverHost string
	if serverPort == 443 {
		serverHost = serverAddress
	} else {
		serverHost = fmt.Sprintf("%s:%d", serverAddress, serverPort)
	}
	dialer, err := newUnderlayDialer(bindInterface, autoDetectInterface, localDNSServer)
	if err != nil {
		return nil, err
	}
	defer dialer.Close()
	tlsKeyLogWriter, err := keylog.Open(debugTLSLogFile)
	if err != nil {
		return nil, fmt.Errorf("open TLS key log: %w", err)
	}
	defer func() {
		if tlsKeyLogWriter != nil {
			if closeErr := tlsKeyLogWriter.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close TLS key log: %w", closeErr))
			}
		}
	}()
	sess := auth.NewSession(serverHost, tlsKeyLogWriter, dialer.DialContext)
	return sess.GetAuthInfoList()
}

func (c *Client) CanUseTCPTunnel() bool {
	return true
}

func (c *Client) NewL3Conn() (io.ReadWriteCloser, error) {
	c.l3TunnelMu.Lock()
	tunnel := c.l3Tunnel
	c.l3TunnelMu.Unlock()
	if tunnel == nil {
		return nil, errors.New("L3 tunnel not initialized")
	}
	return tunnel.NewL3Conn()
}

func SetTrusted(serverAddress string, serverPort int, authData []byte, trusted bool, bindInterface string, autoDetectInterface bool, localDNSServer, debugTLSLogFile string) (err error) {
	var clientAuthData auth.ClientAuthData
	if authData != nil {
		err := json.Unmarshal(authData, &clientAuthData)
		if err != nil {
			log.Println("Error parsing client data:", err)
			return err
		}
	}
	log.DebugPrintf("Given auth data: %+v", clientAuthData)

	if clientAuthData.DeviceID == "" {
		clientAuthData.DeviceID = strings.ToLower(randHex(32))
	}

	var serverHost string
	if serverPort == 443 {
		serverHost = serverAddress
	} else {
		serverHost = fmt.Sprintf("%s:%d", serverAddress, serverPort)
	}
	dialer, err := newUnderlayDialer(bindInterface, autoDetectInterface, localDNSServer)
	if err != nil {
		return err
	}
	defer dialer.Close()
	tlsKeyLogWriter, err := keylog.Open(debugTLSLogFile)
	if err != nil {
		return fmt.Errorf("open TLS key log: %w", err)
	}
	defer func() {
		if tlsKeyLogWriter != nil {
			if closeErr := tlsKeyLogWriter.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close TLS key log: %w", closeErr))
			}
		}
	}()
	sess := auth.NewSession(serverHost, tlsKeyLogWriter, dialer.DialContext)

	if _, err := sess.Login(nil, auth.LoginOptions{
		DeviceID: clientAuthData.DeviceID,
		Cookies:  clientAuthData.Cookies,
	}); err != nil {
		return err
	}
	result, err := sess.QueryDevice()
	if err != nil {
		return err
	}

	if trusted {
		if result.DeviceTrusted {
			log.Println("Device already trusted, skipping")
			return nil
		}
		return sess.TrustDevice([]string{result.SelfID})
	} else {
		if !result.DeviceTrusted {
			log.Println("Device already untrusted, skipping")
			return nil
		}
		return sess.UntrustDevice([]string{result.SelfID})
	}
}

func (c *Client) Setup(serverAddress string, serverPort int, username, password, phone, loginDomain, authType, graphCodeFile, casTicket, oauth2Code, totpSecret string, authData, resourceData []byte, updateBestNodesInterval int) ([]byte, error) {
	if c.underlayDialer == nil {
		return nil, errors.New("underlay dialer is required")
	}
	c.serverAddress = serverAddress

	var clientAuthData auth.ClientAuthData
	if authData != nil {
		if err := json.Unmarshal(authData, &clientAuthData); err != nil {
			log.Println("Error parsing client data:", err)
			return nil, err
		}
	}
	log.DebugPrintf("Given auth data: %+v", clientAuthData)
	if clientAuthData.DeviceID == "" && c.DeviceID != "" {
		clientAuthData.DeviceID = c.DeviceID
	}

	var authServerHost string
	if serverPort == 443 {
		authServerHost = serverAddress
	} else {
		authServerHost = fmt.Sprintf("%s:%d", serverAddress, serverPort)
	}
	sess := auth.NewSession(authServerHost, c.tlsKeyLogWriter, c.underlayDialer.DialContext)
	serverVersionInfo, manifestErr := sess.ServerVersionInfo()
	serverVersionInfo, err := resolveServerVersionInfo(clientAuthData.ServerVersionInfo, serverVersionInfo, manifestErr)
	if err != nil {
		return nil, err
	}
	if manifestErr != nil {
		log.Printf("Failed to refresh aTrust server manifest, using cached version: %v", manifestErr)
	}
	clientAuthData.ServerVersionInfo = serverVersionInfo
	parsedServerVersion, err := auth.ParseServerVersionInfo(serverVersionInfo)
	if err != nil {
		return nil, err
	}
	c.tcpTunnelZeroRTT = parsedServerVersion.TCPTunnelZeroRTT()
	log.Printf("aTrust TCP tunnel zero-RTT: %t", c.tcpTunnelZeroRTT)

	if c.SID != "" && c.DeviceID != "" && resourceData != nil {
		log.Println("Skipping login")

		c.ConnectionID = buildConnectionID(c.DeviceID)
		if c.SignKey == "" {
			c.SignKey = randHex(64)
		}
	} else {
		if clientAuthData.DeviceID == "" {
			clientAuthData.DeviceID = strings.ToLower(randHex(32))
		}
		c.DeviceID = clientAuthData.DeviceID
		c.ConnectionID = buildConnectionID(c.DeviceID)
		c.SignKey = randHex(64)

		if authType == "" {
			if username != "" && password != "" {
				authType = "auth/psw"
			} else if phone != "" {
				authType = "auth/smsCheckCode"
			}
		}

		var err error
		var loginMethod auth.LoginMethod
		switch authType {
		case "auth/psw":
			loginMethod = auth.PasswordLogin{
				Username:      username,
				Password:      password,
				Domain:        loginDomain,
				GraphCodeFile: graphCodeFile,
			}
		case "auth/cas":
			loginMethod = auth.CASLogin{
				Domain: loginDomain,
				Ticket: casTicket,
			}
		case "auth/httpsOauth2":
			loginMethod = auth.HTTPSOauth2Login{
				Domain: loginDomain,
				Code:   oauth2Code,
			}
		case "auth/smsCheckCode":
			loginMethod = auth.SMSLogin{
				Phone:         phone,
				Domain:        loginDomain,
				GraphCodeFile: graphCodeFile,
			}
		case "":
			log.Println("No auth type specified, trying to skip auth")
		default:
			return nil, fmt.Errorf("unsupported auth type: %s", authType)
		}

		loginResult, err := sess.Login(loginMethod, auth.LoginOptions{
			DeviceID:   c.DeviceID,
			Cookies:    clientAuthData.Cookies,
			TOTPSecret: totpSecret,
		})
		if err != nil {
			log.Println("Login error:", err)
			return nil, err
		}
		c.Username = loginResult.Username
		c.SID = loginResult.SID
		clientAuthData.Cookies = loginResult.Cookies

		resourceData, err = sess.ClientResource()
		if err != nil {
			log.Println("Error fetching client resource:", err)
			return nil, err
		}

	}
	authData, err = json.Marshal(clientAuthData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client data: %w", err)
	}

	err = c.parseResource(resourceData)
	if err != nil {
		return nil, err
	}

	log.DebugPrintf("SID: %s, DeviceID: %s, ConnectionID: %s, SignKey: %s", c.SID, c.DeviceID, c.ConnectionID, c.SignKey)

	c.BestNodes = getBestNodes(c.NodeGroups, c.underlayDialer.DialContext, c.tlsKeyLogWriter)

	err = c.getIP()
	if err != nil {
		return nil, err
	}
	c.underlayDialer.ExcludeIP(c.ip)

	l3Tunnel, err := NewL3Tunnel(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create L3 tunnel: %v", err)
	}
	c.l3TunnelMu.Lock()
	c.l3Tunnel = l3Tunnel
	c.l3TunnelMu.Unlock()

	if updateBestNodesInterval > 0 {
		go c.updateBestNodes(c.lifecycleCtx, updateBestNodesInterval)
	}

	return authData, nil
}

func newUnderlayDialer(bindInterface string, autoDetectInterface bool, localDNSServer string) (*underlay.Dialer, error) {
	return underlay.New(underlay.Options{
		InterfaceName:  bindInterface,
		AutoDetect:     autoDetectInterface,
		LocalDNSServer: localDNSServer,
	})
}

func resolveServerVersionInfo(cached, fetched []byte, fetchErr error) ([]byte, error) {
	if fetchErr == nil {
		return fetched, nil
	}
	if len(cached) == 0 {
		return nil, fmt.Errorf("failed to acquire aTrust server manifest: %w", fetchErr)
	}
	return cached, nil
}

func buildConnectionID(deviceID string) string {
	sum := md5.Sum([]byte(deviceID))
	return fmt.Sprintf("%X-%d", sum, time.Now().UnixMicro())
}
