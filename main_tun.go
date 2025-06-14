//go:build tun

package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"github.com/containers/winquit/pkg/winquit"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/service"
	"github.com/mythologyli/zju-connect/stack/tun"
	"golang.org/x/crypto/pkcs12"
	"inet.af/netaddr"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

var conf configs.Config

const zjuConnectVersion = "0.9.0-tun-only"

func main() {
	log.Init()

	log.Println("Start ZJU Connect v" + zjuConnectVersion)
	if conf.DebugDump {
		log.EnableDebug()
	}

	if errs := hook_func.ExecInitialFunc(context.Background(), conf); errs != nil {
		for _, err := range errs {
			log.Printf("Initial ZJU-Connect failed: %s", err)
		}
		os.Exit(1)
	}

	tlsCert := tls.Certificate{}
	if conf.CertFile != "" {
		p12Data, err := os.ReadFile(conf.CertFile)
		if err != nil {
			log.Fatalf("Read certificate file error: %s", err)
		}

		key, cert, err := pkcs12.Decode(p12Data, conf.CertPassword)
		if err != nil {
			log.Fatalf("Decode certificate file error: %s", err)
		}

		tlsCert = tls.Certificate{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key.(crypto.PrivateKey),
			Leaf:        cert,
		}
	}

	vpnClient := easyconnect.NewClient(
		conf.ServerAddress+":"+fmt.Sprintf("%d", conf.ServerPort),
		conf.Username,
		conf.Password,
		conf.TOTPSecret,
		tlsCert,
		conf.TwfID,
		!conf.DisableMultiLine,
		!conf.DisableServerConfig,
		!conf.SkipDomainResource,
	)
	err := vpnClient.Setup()
	if err != nil {
		log.Fatalf("EasyConnect client setup error: %s", err)
	}

	log.Printf("EasyConnect client started")

	ipResources, err := vpnClient.IPResources()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No IP resources")
	}

	ipSet, err := vpnClient.IPSet()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No IP set")
	}

	domainResources, err := vpnClient.DomainResources()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No domain resources")
	}

	dnsResource, err := vpnClient.DNSResource()
	if err != nil && !conf.DisableServerConfig {
		log.Println("No DNS resource")
	}

	if !conf.DisableZJUConfig {
		if domainResources != nil {
			domainResources["zju.edu.cn"] = client.DomainResource{
				PortMin:  1,
				PortMax:  65535,
				Protocol: "all",
			}
		} else {
			domainResources = map[string]client.DomainResource{
				"zju.edu.cn": {
					PortMin:  1,
					PortMax:  65535,
					Protocol: "all",
				},
			}
		}

		if ipResources != nil {
			ipResources = append(ipResources, client.IPResource{
				IPMin:    net.ParseIP("10.0.0.0"),
				IPMax:    net.ParseIP("10.255.255.255"),
				PortMin:  1,
				PortMax:  65535,
				Protocol: "all",
			})
		} else {
			ipResources = []client.IPResource{{
				IPMin:    net.ParseIP("10.0.0.0"),
				IPMax:    net.ParseIP("10.255.255.255"),
				PortMin:  1,
				PortMax:  65535,
				Protocol: "all",
			}}
		}

		ipSetBuilder := netaddr.IPSetBuilder{}
		if ipSet != nil {
			ipSetBuilder.AddSet(ipSet)
		}
		ipSetBuilder.AddPrefix(netaddr.MustParseIPPrefix("10.0.0.0/8"))
		ipSet, _ = ipSetBuilder.IPSet()
	}

	for _, customProxyDomain := range conf.CustomProxyDomain {
		if domainResources != nil {
			domainResources[customProxyDomain] = client.DomainResource{
				PortMin:  1,
				PortMax:  65535,
				Protocol: "all",
			}
		} else {
			domainResources = map[string]client.DomainResource{
				customProxyDomain: {
					PortMin:  1,
					PortMax:  65535,
					Protocol: "all",
				},
			}
		}
	}

	vpnStack, err := tun.NewStack(vpnClient, conf.DNSHijack, ipResources)
	if err != nil {
		log.Fatalf("Tun stack setup error, make sure you are root user : %s", err)
	}

	if conf.AddRoute && ipSet != nil {
		for _, prefix := range ipSet.Prefixes() {
			log.Printf("Add route to %s", prefix.String())
			_ = vpnStack.AddRoute(prefix.String())
		}
	} else if !conf.AddRoute && !conf.DisableZJUConfig {
		log.Println("Add route to 10.0.0.0/8")
		_ = vpnStack.AddRoute("10.0.0.0/8")
	}

	useZJUDNS := !conf.DisableZJUDNS
	zjuDNSServer := conf.ZJUDNSServer
	if useZJUDNS && zjuDNSServer == "auto" {
		zjuDNSServer, err = vpnClient.DNSServer()
		if err != nil {
			useZJUDNS = false
			zjuDNSServer = "10.10.0.21"
			log.Println("No DNS server provided by server. Disable ZJU DNS")
		} else {
			log.Printf("Use DNS server %s provided by server", zjuDNSServer)
		}
	}

	vpnResolver := resolve.NewResolver(
		vpnStack,
		zjuDNSServer,
		conf.SecondaryDNSServer,
		conf.DNSTTL,
		domainResources,
		dnsResource,
		useZJUDNS,
	)

	for _, customDns := range conf.CustomDNSList {
		ipAddr := net.ParseIP(customDns.IP)
		if ipAddr == nil {
			log.Printf("Custom DNS for host name %s is invalid, SKIP", customDns.HostName)
		}
		vpnResolver.SetPermanentDNS(customDns.HostName, ipAddr)
		log.Printf("Add custom DNS: %s -> %s\n", customDns.HostName, customDns.IP)
	}
	localResolver := service.NewDnsServer(vpnResolver, []string{zjuDNSServer, conf.SecondaryDNSServer})
	vpnStack.SetupResolve(localResolver)

	go vpnStack.Run()

	vpnDialer := dial.NewDialer(vpnStack, vpnResolver, ipResources, conf.ProxyAll, conf.DialDirectProxy)

	if conf.DNSServerBind != "" {
		go service.ServeDNS(conf.DNSServerBind, localResolver)
	}
	clientIP, _ := vpnClient.IP()
	go service.ServeDNS(clientIP.String()+":53", localResolver)

	if conf.SocksBind != "" {
		go service.ServeSocks5(conf.SocksBind, vpnDialer, vpnResolver, conf.SocksUser, conf.SocksPasswd)
	}

	if conf.HTTPBind != "" {
		go service.ServeHTTP(conf.HTTPBind, vpnDialer)
	}

	if conf.ShadowsocksURL != "" {
		go service.ServeShadowsocks(vpnDialer, conf.ShadowsocksURL)
	}

	for _, portForwarding := range conf.PortForwardingList {
		if portForwarding.NetworkType == "tcp" {
			go service.ServeTCPForwarding(vpnStack, portForwarding.BindAddress, portForwarding.RemoteAddress)
		} else if portForwarding.NetworkType == "udp" {
			go service.ServeUDPForwarding(vpnStack, portForwarding.BindAddress, portForwarding.RemoteAddress)
		} else {
			log.Printf("Port forwarding: unknown network type %s. Aborting", portForwarding.NetworkType)
		}
	}

	if !conf.DisableKeepAlive {
		if !useZJUDNS {
			log.Println("Keep alive is disabled because ZJU DNS is disabled")
		} else {
			go service.KeepAlive(vpnResolver)
		}
	}

	if runtime.GOOS == "windows" {
		done := make(chan os.Signal, 1)
		signal.Notify(done, syscall.SIGINT)
		winquit.SimulateSigTermOnQuit(done)
		<-done
	} else {
		quit := make(chan os.Signal)
		signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		<-quit
	}
	log.Println("Shutdown ZJU-Connect ......")
	if errs := hook_func.ExecTerminalFunc(context.Background()); errs != nil {
		for _, err := range errs {
			log.Printf("Shutdown ZJU-Connect failed: %s", err)
		}
	} else {
		log.Println("Shutdown ZJU-Connect success, Bye~")
	}
}
