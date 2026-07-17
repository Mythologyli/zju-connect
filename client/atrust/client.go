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
	"github.com/mythologyli/zju-connect/internal/underlay"
	"github.com/mythologyli/zju-connect/log"
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
	domainResources map[string]client.DomainResource
	ipSet           *netaddr.IPSet
	dnsResource     map[string]net.IP
	dnsServer       string

	MajorNodeGroup   string
	NodeGroups       map[string][]string
	BestNodes        map[string]string
	BestNodesRWMutex sync.RWMutex

	ip net.IP // Client IP

	l3Tunnel   *L3Tunnel
	l3TunnelMu sync.Mutex

	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc
	closeOnce       sync.Once
	underlayDialer  *underlay.Dialer
}

func NewClient(username, sid, deviceID, signKey string) *Client {
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	return &Client{
		Username:        username,
		SID:             sid,
		DeviceID:        deviceID,
		SignKey:         signKey,
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

func randHex(n int) string {
	numBytes := (n + 1) / 2
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return strings.ToUpper(hex.EncodeToString(b)[:n])
}

func GetAuthInfoList(serverAddress string, serverPort int, bindInterface string, autoDetectInterface bool) ([]auth.AuthInfo, error) {
	var serverHost string
	if serverPort == 443 {
		serverHost = serverAddress
	} else {
		serverHost = fmt.Sprintf("%s:%d", serverAddress, serverPort)
	}
	dialer := newUnderlayDialer(serverHost, bindInterface, autoDetectInterface)
	sess := auth.NewSession(serverHost, dialer.DialContext)
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

func SetTrusted(serverAddress string, serverPort int, authData []byte, trusted bool, bindInterface string, autoDetectInterface bool) error {
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
	dialer := newUnderlayDialer(serverHost, bindInterface, autoDetectInterface)
	sess := auth.NewSession(serverHost, dialer.DialContext)

	sess.Login(nil, auth.LoginOptions{
		DeviceID: clientAuthData.DeviceID,
		Cookies:  clientAuthData.Cookies,
	})
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

func (c *Client) Setup(serverAddress string, serverPort int, username, password, phone, loginDomain, authType, graphCodeFile, casTicket, oauth2Code string, authData, resourceData []byte, updateBestNodesInterval int, bindInterface string, autoDetectInterface bool) ([]byte, error) {
	c.serverAddress = serverAddress
	serverHost := net.JoinHostPort(serverAddress, fmt.Sprint(serverPort))
	c.underlayDialer = newUnderlayDialer(serverHost, bindInterface, autoDetectInterface)
	if interfaceName := c.underlayDialer.InterfaceName(); interfaceName != "" {
		log.Printf("Underlay interface: %s", interfaceName)
	} else if !autoDetectInterface {
		log.Println("Underlay interface auto detection disabled; using system routing")
	} else {
		log.Println("Warning: failed to detect underlay interface; using system routing")
	}

	if c.SID != "" && c.DeviceID != "" && resourceData != nil {
		log.Println("Skipping login")

		c.ConnectionID = buildConnectionID(c.DeviceID)
		if c.SignKey == "" {
			c.SignKey = randHex(64)
		}
	} else {
		var clientAuthData auth.ClientAuthData
		if authData != nil {
			err := json.Unmarshal(authData, &clientAuthData)
			if err != nil {
				log.Println("Error parsing client data:", err)
				return nil, err
			}
		}
		log.DebugPrintf("Given auth data: %+v", clientAuthData)

		if clientAuthData.DeviceID == "" {
			clientAuthData.DeviceID = strings.ToLower(randHex(32))
		}
		c.DeviceID = clientAuthData.DeviceID
		c.ConnectionID = buildConnectionID(c.DeviceID)
		c.SignKey = randHex(64)

		var authServerHost string
		if serverPort == 443 {
			authServerHost = serverAddress
		} else {
			authServerHost = fmt.Sprintf("%s:%d", serverAddress, serverPort)
		}
		sess := auth.NewSession(authServerHost, c.underlayDialer.DialContext)

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
			DeviceID: c.DeviceID,
			Cookies:  clientAuthData.Cookies,
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

		authData, err = json.Marshal(clientAuthData)
		if err != nil {
			log.Println("Error marshaling auth data:", err)
		}
	}

	err := c.parseResource(resourceData)
	if err != nil {
		return nil, err
	}

	log.DebugPrintf("SID: %s, DeviceID: %s, ConnectionID: %s, SignKey: %s", c.SID, c.DeviceID, c.ConnectionID, c.SignKey)

	c.BestNodes = getBestNodes(c.NodeGroups, c.underlayDialer.DialContext)

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

func newUnderlayDialer(serverHost, bindInterface string, autoDetectInterface bool) *underlay.Dialer {
	return underlay.New(serverHost, underlay.Options{
		InterfaceName: bindInterface,
		AutoDetect:    autoDetectInterface,
	})
}

func buildConnectionID(deviceID string) string {
	sum := md5.Sum([]byte(deviceID))
	return fmt.Sprintf("%X-%d", sum, time.Now().UnixMicro())
}
