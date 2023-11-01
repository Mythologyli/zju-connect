package client

import (
	"crypto/tls"
	"errors"
	"github.com/mythologyli/zju-connect/log"
	"inet.af/netaddr"
	"net"
	"net/http"
	"time"
)

type EasyConnectClient struct {
	server        string // Example: rvpn.zju.edu.cn:443. No protocol prefix
	username      string
	password      string
	testMultiLine bool
	parseResource bool

	httpClient *http.Client

	twfID string
	token *[48]byte

	lineList []string

	ipResource     *netaddr.IPSet
	domainResource map[string]bool
	dnsResource    map[string]net.IP

	ip        net.IP // Client IP
	ipReverse []byte
}

func NewEasyConnectClient(server, username, password, twfID string, testMultiLine, parseResource bool) *EasyConnectClient {
	return &EasyConnectClient{
		server:        server,
		username:      username,
		password:      password,
		testMultiLine: testMultiLine,
		parseResource: parseResource,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}},
		twfID: twfID,
	}
}

func (c *EasyConnectClient) IP() (net.IP, error) {
	if c.ip == nil {
		return nil, errors.New("IP not available")
	}

	return c.ip, nil
}

func (c *EasyConnectClient) IPResource() (*netaddr.IPSet, error) {
	if c.ipResource == nil {
		return nil, errors.New("IP resource not available")
	}

	return c.ipResource, nil
}

func (c *EasyConnectClient) DomainResource() (map[string]bool, error) {
	if c.domainResource == nil {
		return nil, errors.New("domain resource not available")
	}

	return c.domainResource, nil
}

func (c *EasyConnectClient) DNSResource() (map[string]net.IP, error) {
	if c.dnsResource == nil {
		return nil, errors.New("DNS resource not available")
	}

	return c.dnsResource, nil
}

func (c *EasyConnectClient) Setup() error {
	// Use username/password/(SMS code) to get the TwfID
	if c.twfID == "" {
		err := c.requestTwfID()
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

						return c.Setup()
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

	return nil
}
