//go:build !tun

package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/service"
	"github.com/mythologyli/zju-connect/stack"
	"github.com/mythologyli/zju-connect/stack/gvisor"
	"github.com/mythologyli/zju-connect/stack/tun"
	"golang.org/x/crypto/pkcs12"
	"inet.af/netaddr"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var conf configs.Config

const zjuConnectVersion = "0.8.0"

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

	vpnClient := client.NewEasyConnectClient(
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

	ipResource, err := vpnClient.IPResource()
	if err != nil && !conf.DisableMultiLine {
		log.Println("No IP resource")
	}

	domainResource, err := vpnClient.DomainResource()
	if err != nil && !conf.DisableMultiLine {
		log.Println("No domain resource")
	}

	dnsResource, err := vpnClient.DNSResource()
	if err != nil && !conf.DisableMultiLine {
		log.Println("No DNS resource")
	}

	if !conf.DisableZJUConfig {
		if domainResource != nil {
			domainResource["zju.edu.cn"] = true
		} else {
			domainResource = map[string]bool{"zju.edu.cn": true}
		}

		ipSetBuilder := netaddr.IPSetBuilder{}
		if ipResource != nil {
			ipSetBuilder.AddSet(ipResource)
		}
		ipSetBuilder.AddPrefix(netaddr.MustParseIPPrefix("10.0.0.0/8"))
		ipResource, _ = ipSetBuilder.IPSet()
	}

	for _, customProxyDomain := range conf.CustomProxyDomain {
		domainResource[customProxyDomain] = true
	}

	var vpnStack stack.Stack
	if conf.TUNMode {
		vpnTUNStack, err := tun.NewStack(vpnClient, conf.DNSHijack)
		if err != nil {
			log.Fatalf("Tun stack setup error, make sure you are root user : %s", err)
		}

		if conf.AddRoute && ipResource != nil {
			for _, prefix := range ipResource.Prefixes() {
				log.Printf("Add route to %s", prefix.String())
				_ = vpnTUNStack.AddRoute(prefix.String())
			}
		}

		vpnStack = vpnTUNStack
	} else {
		vpnStack, err = gvisor.NewStack(vpnClient)
		if err != nil {
			log.Fatalf("gVisor stack setup error: %s", err)
		}
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
		domainResource,
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

	vpnDialer := dial.NewDialer(vpnStack, vpnResolver, ipResource, conf.ProxyAll, conf.DialDirectProxy)

	if conf.DNSServerBind != "" {
		go service.ServeDNS(conf.DNSServerBind, localResolver)
	}
	if conf.TUNMode {
		clientIP, _ := vpnClient.IP()
		go service.ServeDNS(clientIP.String()+":53", localResolver)
	}

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

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	<-quit
	log.Println("Shutdown ZJU-Connect ......")
	if errs := hook_func.ExecTerminalFunc(context.Background()); errs != nil {
		for _, err := range errs {
			log.Printf("Shutdown ZJU-Connect failed: %s", err)
		}
	} else {
		log.Println("Shutdown ZJU-Connect success, Bye~")
	}
}
