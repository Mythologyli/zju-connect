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
	"github.com/mythologyli/zju-connect/client/authchallenge"
	"github.com/mythologyli/zju-connect/internal/ipresource"
	"github.com/mythologyli/zju-connect/internal/keylog"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/underlay"
	"inet.af/netaddr"
)

type SessionOptions struct {
	Username     string
	SID          string
	DeviceID     string
	MACAddresses []string
	SignKey      string
	SIDTicket    string
}

type ClientOptions struct {
	Session         SessionOptions
	UnderlayDialer  client.UnderlayDialer
	TLSKeyLogWriter io.Writer
}

type SetupOptions struct {
	ServerAddress            string
	ServerPort               int
	LoginMethod              auth.LoginMethod
	TOTPSecret               string
	ClientData               []byte
	ResourceData             []byte
	BestNodesRefreshInterval time.Duration
	ChallengeHandler         authchallenge.Handler
	SessionRefreshInterval   time.Duration
	// AutoRelogin lets the recovery ladder repeat a full login when a renewal and
	// a restore both failed. It is off by default: a full login rotates the device
	// token and drops other clients of the same account.
	AutoRelogin    bool
	SaveClientData func([]byte) error
}

type Client struct {
	Username     string
	SID          string
	DeviceID     string
	MACAddresses []string
	ConnectionID string
	SignKey      string
	// SIDTicket is the portal-issued ticket the restore path exchanges for a
	// session; it is the material that survives a restart without a password.
	SIDTicket string

	sessionMu   sync.RWMutex
	sessionErr  error
	refreshDone chan struct{}

	// Session maintenance: the session itself, the material a restart needs, and
	// what the last recovery learned. All of it is guarded by sessionMu, except
	// session and clientAuthData, which are written once during setup before any
	// goroutine reads them (and read under the lock afterwards).
	session        *auth.Session
	clientAuthData auth.ClientAuthData
	saveClientData func([]byte) error
	lastPersisted  []byte
	loginMethod    auth.LoginMethod
	loginOptions   auth.LoginOptions
	autoRelogin    bool
	reloginBlocked bool
	sessionState   SessionState
	recovering     bool
	lastRecovery   time.Time

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

func NewClient(options ClientOptions) *Client {
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	return &Client{
		Username:        options.Session.Username,
		SID:             options.Session.SID,
		DeviceID:        options.Session.DeviceID,
		MACAddresses:    options.Session.MACAddresses,
		SignKey:         options.Session.SignKey,
		SIDTicket:       options.Session.SIDTicket,
		underlayDialer:  options.UnderlayDialer,
		tlsKeyLogWriter: options.TLSKeyLogWriter,
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
	}
}

func (c *Client) canResume(resourceData []byte) bool {
	if c.SID == "" || c.DeviceID == "" || resourceData == nil {
		return false
	}
	if c.SignKey == "" {
		// A resume must supply the sign key the session was minted with, because
		// the server checks it together with the device id. Minting a fresh one
		// here is how a "connected but dead" tunnel is produced: the L3 tunnel
		// comes up, a VIP is allocated, and every authorization through it is
		// rejected (code 10000030 sig or deviceId verify failed).
		log.Println("Not resuming: the stored session has no sign key (it is stored with the device id); " +
			"a fresh login is required")
		return false
	}
	return true
}

// canRestoreByTicket reports whether a sidTicket can be exchanged for a session.
// The exchange runs on the cookie family the portal issues, so no stored cookie is
// required - but the restored session still has to present the sign key it was
// minted with, and a resource list to work from.
func (c *Client) canRestoreByTicket(resourceData []byte) bool {
	return c.SIDTicket != "" && c.DeviceID != "" && c.SignKey != "" && resourceData != nil
}

func (c *Client) Close() {
	c.closeOnce.Do(func() {
		c.lifecycleCancel()
		if c.refreshDone != nil {
			<-c.refreshDone
		}
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
	log.DebugPrintf("Given auth data: device=%s cookies=%d sign_key=%s sid_ticket=%s",
		clientAuthData.DeviceID, len(clientAuthData.Cookies),
		log.Redact(clientAuthData.SignKey), log.Redact(clientAuthData.SIDTicket))

	if clientAuthData.DeviceID == "" {
		clientAuthData.DeviceID = strings.ToLower(randHex(32))
	}
	if len(clientAuthData.MACAddresses) == 0 {
		clientAuthData.MACAddresses = []string{randMACAddress()}
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
		DeviceID:     clientAuthData.DeviceID,
		MACAddresses: clientAuthData.MACAddresses,
		Cookies:      clientAuthData.Cookies,
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

type sessionEstablishment struct {
	resourceData []byte
	resumed      bool
	restored     bool
}

// establishSession is the single owner of the resume / ticket-restore / login
// decision. The predicates and the action live together, so a combination the
// caller believes is documented cannot pass one check and then call Login with a
// nil method. The resource list is an input only for a resume; a restored session
// fetches it through the authenticated session, exactly like a login does.
func (c *Client) establishSession(
	ctx context.Context,
	sess *auth.Session,
	options SetupOptions,
	clientAuthData *auth.ClientAuthData,
	resourceData []byte,
) (sessionEstablishment, error) {
	established := sessionEstablishment{resourceData: resourceData}
	established.resumed = c.canResume(established.resourceData)

	switch {
	case established.resumed:
		log.Println("Skipping login")

		c.ConnectionID = buildConnectionID(c.DeviceID)
		sess.Restore(c.DeviceID, c.SID, clientAuthData.Cookies)
		return established, nil
	case c.canRestoreByTicket(established.resourceData):
		log.Println("Restoring the aTrust session from a sidTicket")

		c.ConnectionID = buildConnectionID(c.DeviceID)
		if _, err := sess.RestoreByTicket(ctx, c.SIDTicket); err != nil {
			// A ticket that cannot be exchanged is not fatal: fall through to a
			// login, which is what the recovery ladder does too.
			log.Printf("aTrust sidTicket restore failed, logging in instead: %v", err)
		} else {
			established.restored = true
			return established, nil
		}
	}

	if clientAuthData.DeviceID == "" {
		clientAuthData.DeviceID = strings.ToLower(randHex(32))
	}
	c.DeviceID = clientAuthData.DeviceID
	c.ConnectionID = buildConnectionID(c.DeviceID)
	c.SignKey = randHex(64)
	if len(clientAuthData.MACAddresses) == 0 {
		clientAuthData.MACAddresses = []string{randMACAddress()}
	}
	c.MACAddresses = clientAuthData.MACAddresses

	if options.LoginMethod == nil {
		log.Println("No auth type specified, trying to skip auth")
	}

	loginResult, err := sess.Login(options.LoginMethod, auth.LoginOptions{
		DeviceID:         c.DeviceID,
		MACAddresses:     c.MACAddresses,
		Cookies:          clientAuthData.Cookies,
		TOTPSecret:       options.TOTPSecret,
		ChallengeHandler: options.ChallengeHandler,
	})
	if err != nil {
		log.Println("Login error:", err)
		return established, err
	}
	c.Username = loginResult.Username

	established.resourceData, err = sess.ClientResource()
	if err != nil {
		log.Println("Error fetching client resource:", err)
		return established, err
	}
	return established, nil
}

func (c *Client) Setup(options SetupOptions) ([]byte, error) {
	return c.SetupContext(context.Background(), options)
}

func (c *Client) SetupContext(ctx context.Context, options SetupOptions) ([]byte, error) {
	setupCtx, cancelSetup := context.WithCancel(ctx)
	defer cancelSetup()
	stopLifecycleCancellation := context.AfterFunc(c.lifecycleCtx, cancelSetup)
	defer stopLifecycleCancellation()
	if err := setupCtx.Err(); err != nil {
		return nil, err
	}
	if c.underlayDialer == nil {
		return nil, errors.New("underlay dialer is required")
	}
	c.serverAddress = options.ServerAddress

	var clientAuthData auth.ClientAuthData
	if options.ClientData != nil {
		if err := json.Unmarshal(options.ClientData, &clientAuthData); err != nil {
			log.Println("Error parsing client data:", err)
			return nil, err
		}
	}
	log.DebugPrintf("Given auth data: device=%s cookies=%d sign_key=%s sid_ticket=%s",
		clientAuthData.DeviceID, len(clientAuthData.Cookies),
		log.Redact(clientAuthData.SignKey), log.Redact(clientAuthData.SIDTicket))
	if clientAuthData.DeviceID == "" && c.DeviceID != "" {
		clientAuthData.DeviceID = c.DeviceID
	}
	if c.SignKey == "" {
		// The stored key is the one the session was minted with; never replace it
		// with a fresh one for a stored session (see canResume).
		c.SignKey = clientAuthData.SignKey
	}
	if c.SIDTicket == "" {
		c.SIDTicket = clientAuthData.SIDTicket
	}
	if len(clientAuthData.MACAddresses) == 0 && len(c.MACAddresses) > 0 {
		clientAuthData.MACAddresses = c.MACAddresses
	}

	var authServerHost string
	if options.ServerPort == 443 {
		authServerHost = options.ServerAddress
	} else {
		authServerHost = fmt.Sprintf("%s:%d", options.ServerAddress, options.ServerPort)
	}
	sess := auth.NewSessionContext(setupCtx, authServerHost, c.tlsKeyLogWriter, c.underlayDialer.DialContext)
	c.sessionMu.Lock()
	c.session = sess
	c.sessionMu.Unlock()
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

	establishment, err := c.establishSession(setupCtx, sess, options, &clientAuthData, options.ResourceData)
	if err != nil {
		return nil, err
	}
	resourceData := establishment.resourceData
	resumed := establishment.resumed
	restoredFromTicket := establishment.restored

	snapshot, err := sess.Snapshot()
	if err != nil {
		return nil, err
	}
	c.setSessionSID(snapshot.SID, nil)
	clientAuthData.DeviceID = c.DeviceID
	clientAuthData.Cookies = snapshot.Cookies
	clientAuthData.SignKey = c.SignKey
	clientAuthData.CSRFToken = sess.CSRFToken()
	if c.SIDTicket != "" {
		clientAuthData.SIDTicket = c.SIDTicket
	}

	// The session is no longer the setup call's: it now belongs to the client, on
	// a context that lives as long as the client does. The setup context is
	// cancelled the moment this function returns, and a session holding it can
	// neither renew nor notice that the session died.
	sess.SetLifetime(c.lifecycleCtx)

	c.sessionMu.Lock()
	c.clientAuthData = clientAuthData
	c.saveClientData = options.SaveClientData
	c.loginMethod = options.LoginMethod
	c.loginOptions = auth.LoginOptions{
		DeviceID:         c.DeviceID,
		TOTPSecret:       options.TOTPSecret,
		ChallengeHandler: options.ChallengeHandler,
	}
	c.autoRelogin = options.AutoRelogin
	c.sessionMu.Unlock()

	authData := c.persistAuthData()
	if authData == nil {
		return nil, fmt.Errorf("failed to marshal client data")
	}

	// Take the restore ticket now, while the session is known to be alive: the
	// exchange needs a live session, so it cannot be the thing the ladder does
	// after the session died.
	c.prepareRestoreTicket(setupCtx, sess)

	err = c.parseResource(resourceData)
	if err != nil {
		return nil, err
	}

	log.DebugPrintf("SID: %s, DeviceID: %s, ConnectionID: %s, SignKey: %s", c.SID, c.DeviceID, c.ConnectionID, c.SignKey)

	c.BestNodes = getBestNodes(setupCtx, c.NodeGroups, c.underlayDialer.DialContext, c.tlsKeyLogWriter)
	if err := setupCtx.Err(); err != nil {
		return nil, err
	}

	err = c.getIP(setupCtx)
	if err != nil {
		return nil, err
	}
	c.underlayDialer.ExcludeIP(c.ip)

	if err := setupCtx.Err(); err != nil {
		return nil, err
	}
	l3Tunnel, err := NewL3Tunnel(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create L3 tunnel: %v", err)
	}
	c.l3TunnelMu.Lock()
	c.l3Tunnel = l3Tunnel
	c.l3TunnelMu.Unlock()
	if options.SessionRefreshInterval > 0 {
		c.startSessionRefresh(sess.Refresh, options.SessionRefreshInterval)
	}

	// A login has just been validated by the portal, so the session is online. A
	// resumed one has only been pointed at the stored SID: the tunnel comes up
	// while the data plane may reject everything (a mismatched sign key does
	// exactly that), so it stays unproven until traffic crosses it.
	if resumed || restoredFromTicket {
		c.setSessionState(SessionRestoring, "session restored from stored material", 0)
	} else {
		c.setSessionState(SessionOnline, "logged in", 0)
	}

	if options.BestNodesRefreshInterval > 0 {
		go c.updateBestNodes(c.lifecycleCtx, options.BestNodesRefreshInterval)
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

func randMACAddress() string {
	mac := make([]byte, 6)
	if _, err := rand.Read(mac); err != nil {
		panic(err)
	}
	mac[0] = mac[0]&0xfe | 0x02 // locally administered, unicast
	return net.HardwareAddr(mac).String()
}
