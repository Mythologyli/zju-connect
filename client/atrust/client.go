package atrust

import (
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

	l3Tunnel *L3Tunnel
}

func NewClient(username, sid, deviceID, connectionID, signKey string) *Client {
	return &Client{
		Username:     username,
		SID:          sid,
		DeviceID:     deviceID,
		ConnectionID: connectionID,
		SignKey:      signKey,
	}
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

func GetAuthInfoList(serverAddress string, serverPort int) ([]auth.AuthInfo, error) {
	var serverHost string
	if serverPort == 443 {
		serverHost = serverAddress
	} else {
		serverHost = fmt.Sprintf("%s:%d", serverAddress, serverPort)
	}
	sess := auth.NewSession(serverHost)
	return sess.GetAuthInfoList()
}

func (c *Client) CanUseTCPTunnel() bool {
	return true
}

func (c *Client) NewL3Conn() (io.ReadWriteCloser, error) {
	return c.l3Tunnel.NewL3Conn()
}

func (c *Client) Setup(serverAddress string, serverPort int, username, password, phone, loginDomain, authType, graphCodeFile, casTicket string, authData, resourceData []byte) ([]byte, error) {
	c.serverAddress = serverAddress

	if c.SID != "" && c.DeviceID != "" && resourceData != nil {
		log.Println("Skipping login")

		if c.ConnectionID == "" {
			c.ConnectionID = randHex(32)
		}
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

		var serverHost string
		if serverPort == 443 {
			serverHost = serverAddress
		} else {
			serverHost = fmt.Sprintf("%s:%d", serverAddress, serverPort)
		}
		sess := auth.NewSession(serverHost)

		var err error
		c.Username, c.SID, clientAuthData.Cookies, err = sess.Login(username, password, phone, loginDomain, authType, c.DeviceID, graphCodeFile, casTicket, clientAuthData.Cookies)
		if err != nil {
			log.Println("Login error:", err)
			return nil, err
		}

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

	c.BestNodes = getBestNodes(c.NodeGroups)

	err = c.getIP()
	if err != nil {
		return nil, err
	}

	c.l3Tunnel, err = NewL3Tunnel(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create L3 tunnel: %v", err)
	}

	return authData, nil
}

func buildConnectionID(deviceID string) string {
	sum := md5.Sum([]byte(deviceID))
	return fmt.Sprintf("%X-%d", sum, time.Now().UnixMicro())
}
