package tun

import (
	"context"
	"fmt"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/terminal_func"
	"github.com/mythologyli/zju-connect/log"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"net"
	"net/netip"
	"os/exec"
	"sync"
)

const guid = "{4F5CDE94-D2A3-4AA5-A4A3-0FE6CB909E83}"
const interfaceName = "ZJU Connect"

type Endpoint struct {
	easyConnectClient *client.EasyConnectClient

	dev       tun.Device
	readLock  sync.Mutex
	writeLock sync.Mutex
	ip        net.IP
}

func (ep *Endpoint) Write(buf []byte) error {
	ep.writeLock.Lock()
	defer ep.writeLock.Unlock()
	bufs := [][]byte{buf}

	_, err := ep.dev.Write(bufs, 0)
	if err != nil {
		return err
	}

	return nil
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
	err = command.Run()
	if err != nil {
		return err
	}

	return nil
}

func NewStack(easyConnectClient *client.EasyConnectClient, dnsHijack bool) (*Stack, error) {
	s := &Stack{}

	guid, err := windows.GUIDFromString(guid)
	if err != nil {
		return nil, err
	}

	dev, err := tun.CreateTUNWithRequestedGUID(interfaceName, &guid, int(MTU))
	if err != nil {
		return nil, err
	}

	s.endpoint = &Endpoint{
		easyConnectClient: easyConnectClient,
	}

	s.endpoint.dev = dev

	nativeTunDevice := dev.(*tun.NativeTun)

	link := winipcfg.LUID(nativeTunDevice.LUID())

	s.endpoint.ip, err = easyConnectClient.IP()
	if err != nil {
		return nil, err
	}

	prefix, err := netip.ParsePrefix(s.endpoint.ip.String() + "/8")
	if err != nil {
		log.Printf("Parse prefix failed: %v", err) // Fail to set TUN IP is not a fatal problem, so we don't return an error
	}

	err = link.SetIPAddresses([]netip.Prefix{prefix})
	if err != nil {
		log.Printf("Set IP address failed: %v", err)
	}

	// Set MTU to 1400 otherwise error may occur when packets are large
	command := exec.Command("netsh", "interface", "ipv4", "set", "subinterface", interfaceName, fmt.Sprintf("mtu=%d", MTU), "store=persistent")
	err = command.Run()
	if err != nil {
		log.Printf("Run %s failed: %v", command.String(), err)
	}

	// We must add a route to 0.0.0.0/0, otherwise Windows will refuse to send packets to public network via TUN interface
	// Set metric to 9999 to make sure normal traffic not go through TUN interface
	command = exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", s.endpoint.ip.String(), "metric", "9999")
	err = command.Run()
	if err != nil {
		log.Printf("Run %s failed: %v", command.String(), err)
	}

	if dnsHijack {
		command = exec.Command("netsh", "interface", "ipv4", "add", "dnsservers", "ZJU Connect", s.endpoint.ip.String())
	} else {
		command = exec.Command("netsh", "interface", "ipv4", "delete", "dnsservers", "ZJU Connect", "all")
	}
	err = command.Run()
	if err != nil {
		log.Printf("Run %s failed: %v", command.String(), err)
	}

	terminal_func.RegisterTerminalFunc("Close Tun Device", func(ctx context.Context) error {
		dev.Close()
		closeCommand := exec.Command("netsh", "interface", "ipv4", "delete", "dnsservers", "ZJU Connect", "all")
		return closeCommand.Run()
	})
	return s, nil
}
