package atrustl3

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sync"

	"github.com/mythologyli/zju-connect/client"
	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const guid = "{4F5CDE94-D2A3-4AA5-A4A3-0FE6CB909E83}"
const interfaceName = "ZJU Connect"

type Endpoint struct {
	dev       tun.Device
	readLock  sync.Mutex
	writeLock sync.Mutex
	ip        net.IP
}

func (ep *Endpoint) Write(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	ep.writeLock.Lock()
	defer ep.writeLock.Unlock()
	bufs := [][]byte{buf}

	_, err := ep.dev.Write(bufs, 0)
	return err
}

func (ep *Endpoint) Read(buf []byte) (int, error) {
	ep.readLock.Lock()
	defer ep.readLock.Unlock()
	bufs := [][]byte{buf}
	sizes := []int{1}

	_, err := ep.dev.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}

	return sizes[0], nil
}

func (s *Stack) AddRoute(target string) error {
	ipaddr, ipv4Net, err := net.ParseCIDR(target)
	if err != nil {
		return err
	}

	ip := ipaddr.To4()
	if ip == nil {
		return fmt.Errorf("not a valid IPv4 address")
	}

	command := exec.Command("route", "add", ip.String(), "mask", net.IP(ipv4Net.Mask).String(), s.endpoint.ip.String(), "metric", "1")
	return command.Run()
}

func NewStack(aTrustClient *atrustclient.Client, dnsHijack bool, ipResources []client.IPResource) (*Stack, error) {
	s, err := newStack(aTrustClient)
	if err != nil {
		return nil, err
	}
	if ipResources != nil {
		s.ipResources = ipResources
	}

	guid, err := windows.GUIDFromString(guid)
	if err != nil {
		return nil, err
	}

	dev, err := tun.CreateTUNWithRequestedGUID(interfaceName, &guid, int(MTU))
	if err != nil {
		return nil, err
	}

	s.endpoint = &Endpoint{dev: dev, ip: s.ip}

	nativeTunDevice := dev.(*tun.NativeTun)
	link := winipcfg.LUID(nativeTunDevice.LUID())

	prefix, err := netip.ParsePrefix(s.endpoint.ip.String() + "/32")
	if err != nil {
		log.Printf("Parse prefix failed: %v", err)
	}

	err = link.SetIPAddresses([]netip.Prefix{prefix})
	if err != nil {
		log.Printf("Set IP address failed: %v", err)
	}

	command := exec.Command("netsh", "interface", "ipv4", "set", "subinterface", interfaceName, fmt.Sprintf("mtu=%d", MTU), "store=persistent")
	if err := command.Run(); err != nil {
		log.Printf("Run %s failed: %v", command.String(), err)
	}

	command = exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", s.endpoint.ip.String(), "metric", "9999")
	if err := command.Run(); err != nil {
		log.Printf("Run %s failed: %v", command.String(), err)
	}

	if dnsHijack {
		command = exec.Command("netsh", "interface", "ipv4", "add", "dnsservers", interfaceName, s.endpoint.ip.String())
	} else {
		command = exec.Command("netsh", "interface", "ipv4", "delete", "dnsservers", interfaceName, "all")
	}
	if err := command.Run(); err != nil {
		log.Printf("Run %s failed: %v", command.String(), err)
	}

	hook_func.RegisterTerminalFunc("Close Tun Device", func(ctx context.Context) error {
		dev.Close()
		closeCommand := exec.Command("netsh", "interface", "ipv4", "delete", "dnsservers", interfaceName, "all")
		return closeCommand.Run()
	})

	return s, nil
}
