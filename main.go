package main

import (
	"context"
	"fmt"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/service"
	"github.com/mythologyli/zju-connect/stack"
	"github.com/mythologyli/zju-connect/stack/gvisor"
	"github.com/mythologyli/zju-connect/stack/tun"
	"inet.af/netaddr"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var conf Config

const zjuConnectVersion = "0.6.0"

func main() {
	log.Init()

	log.Println("Start ZJU Connect v" + zjuConnectVersion)
	if conf.DebugDump {
		log.EnableDebug()
	}

	if errs := hook_func.ExecInitialFunc(context.Background()); errs != nil {
		for _, err := range errs {
			log.Printf("Initial ZJU-Connect failed:", err)
		}
		os.Exit(1)
	}

	vpnClient := client.NewEasyConnectClient(
		conf.ServerAddress+":"+fmt.Sprintf("%d", conf.ServerPort),
		conf.Username,
		conf.Password,
		conf.TwfID,
		!conf.DisableMultiLine,
		!conf.DisableServerConfig,
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

	vpnResolver := resolve.NewResolver(
		vpnStack,
		conf.ZJUDNSServer,
		conf.SecondaryDNSServer,
		conf.DNSTTL,
		domainResource,
		dnsResource,
		!conf.DisableZJUDNS,
	)

	for _, customDns := range conf.CustomDNSList {
		ipAddr := net.ParseIP(customDns.IP)
		if ipAddr == nil {
			log.Printf("Custom DNS for host name %s is invalid, SKIP", customDns.HostName)
		}
		vpnResolver.SetPermanentDNS(customDns.HostName, ipAddr)
		log.Printf("Add custom DNS: %s -> %s\n", customDns.HostName, customDns.IP)
	}
	localResolver := service.NewDnsServer(vpnResolver, []string{conf.ZJUDNSServer, conf.SecondaryDNSServer})
	vpnStack.SetupResolve(localResolver)

	go vpnStack.Run()

	vpnDialer := dial.NewDialer(vpnStack, vpnResolver, ipResource, conf.ProxyAll)

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
		go service.KeepAlive(vpnResolver)
	}

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Println("Shutdown ZJU-Connect ......")
	if errs := hook_func.ExecTerminalFunc(context.Background()); errs != nil {
		for _, err := range errs {
			log.Printf("Shutdown ZJU-Connect failed:", err)
		}
	} else {
		log.Println("Shutdown ZJU-Connect success, Bye~")
	}
}
