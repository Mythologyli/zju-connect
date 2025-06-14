package atrust

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/client/atrust/auth"
	"github.com/mythologyli/zju-connect/client/atrust/auth/zju"
	"github.com/mythologyli/zju-connect/log"
	"inet.af/netaddr"
	"net"
	"strings"
)

type Client struct {
	Username     string
	Password     string
	SID          string
	DeviceID     string
	ConnectionID string
	SignKey      string

	ipResources     []client.IPResource
	domainResources map[string]client.DomainResource
	ipSet           *netaddr.IPSet
	dnsResource     map[string]net.IP
	dnsServer       string

	NodeGroups map[string][]string
}

func NewClient(username, password, sid, deviceID, connectionID, signKey string) *Client {
	return &Client{
		Username:     username,
		Password:     password,
		SID:          sid,
		DeviceID:     deviceID,
		ConnectionID: connectionID,
		SignKey:      signKey,
	}
}

func (c *Client) IPSet() (*netaddr.IPSet, error) {
	if c.ipSet == nil {
		return nil, nil
	}
	return c.ipSet, nil
}

func (c *Client) IPResources() ([]client.IPResource, error) {
	if c.ipResources == nil {
		return nil, nil
	}
	return c.ipResources, nil
}

func (c *Client) DomainResources() (map[string]client.DomainResource, error) {
	if c.domainResources == nil {
		return nil, nil
	}
	return c.domainResources, nil
}

func (c *Client) DNSResource() (map[string]net.IP, error) {
	if c.dnsResource == nil {
		return nil, nil
	}
	return c.dnsResource, nil
}

func (c *Client) DNSServer() (string, error) {
	if c.dnsServer == "" {
		return "", nil
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

func (c *Client) Setup(authType, graphCodeFile string, authData, resourceData []byte) ([]byte, error) {
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

		if clientAuthData.DeviceID == "" {
			clientAuthData.DeviceID = randHex(32)
		}
		c.DeviceID = clientAuthData.DeviceID
		if clientAuthData.ConnectionID == "" {
			clientAuthData.ConnectionID = randHex(32)
		}
		c.ConnectionID = clientAuthData.ConnectionID
		c.SignKey = randHex(64)

		log.Printf("Starting login with auth type: %s", authType)
		if authType == "zju" {
			sess := zju.NewSession()

			var err error
			c.SID, clientAuthData.Cookies, err = sess.Login(c.Username, c.Password, c.DeviceID, graphCodeFile, clientAuthData.Cookies)
			if err != nil {
				log.Println("Login error:", err)
				return nil, err
			}

			resourceData, err = sess.ClientResource()
			if err != nil {
				log.Println("Error fetching client resource:", err)
				return nil, err
			}
		} else {
			log.Println("Unsupported auth type:", authType)
			return nil, fmt.Errorf("unsupported auth type: %s", authType)
		}

		var err error
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

	return authData, nil
}
