package core

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"log"
	"net/netip"
	"os/exec"
)

type EasyConnectTunEndpoint struct {
	dev tun.Device
}

func (ep *EasyConnectTunEndpoint) Write(buf []byte) error {
	bufs := [][]byte{buf}

	_, err := ep.dev.Write(bufs, 0)
	if err != nil {
		return err
	}

	return nil
}

func (ep *EasyConnectTunEndpoint) Read(buf []byte) (int, error) {
	bufs := make([][]byte, 1)
	for i := range bufs {
		bufs[i] = make([]byte, 1500)
	}

	sizes := make([]int, 1)

	_, err := ep.dev.Read(bufs, sizes, 0)
	if err != nil {
		return 0, err
	}

	copy(buf, bufs[0][:sizes[0]])

	return sizes[0], nil
}

func SetupTunStack(ip []byte, endpoint *EasyConnectTunEndpoint) {
	guid, err := windows.GUIDFromString("{4F5CDE94-D2A3-4AA5-A4A3-0FE6CB909E83}")
	if err != nil {
		panic(err)
	}

	dev, err := tun.CreateTUNWithRequestedGUID("ZJU Connect", &guid, 1400)
	if err != nil {
		panic(err)
	}

	endpoint.dev = dev

	nativeTunDevice := dev.(*tun.NativeTun)

	link := winipcfg.LUID(nativeTunDevice.LUID())

	ipStr := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])

	prefix, err := netip.ParsePrefix(ipStr + "/8")
	if err != nil {
		log.Printf("ParsePrefix failed: %v", err)
	}

	err = link.SetIPAddresses([]netip.Prefix{prefix})
	if err != nil {
		log.Printf("SetIPAddresses failed: %v", err)
	}

	cmd := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", ipStr, "metric", "9999")
	err = cmd.Run()
	if err != nil {
		log.Printf("Run route add failed: %v", err)
	}
}
