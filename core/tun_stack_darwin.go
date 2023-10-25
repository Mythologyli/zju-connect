package core

import (
	"fmt"
	"github.com/songgao/water"
	"log"
	"os/exec"
)

type EasyConnectTunEndpoint struct {
	ifce *water.Interface
}

func (ep *EasyConnectTunEndpoint) Write(buf []byte) error {
	_, err := ep.ifce.Write(buf)
	return err
}

func (ep *EasyConnectTunEndpoint) Read(buf []byte) (int, error) {
	return ep.ifce.Read(buf)
}

func (ep *EasyConnectTunEndpoint) AddRoute(target string) error {
	command := exec.Command("route", "-n", "add", "-net", target, "-interface", ep.ifce.Name())
	err := command.Run()
	if err != nil {
		return err
	}

	return nil
}

func SetupTunStack(ip []byte, endpoint *EasyConnectTunEndpoint) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Interface Name: %s\n", ifce.Name())

	endpoint.ifce = ifce

	ipStr := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	cmd := exec.Command("ifconfig", ifce.Name(), ipStr, "255.0.0.0", ipStr)
	err = cmd.Run()
	if err != nil {
		log.Printf("Run %s failed: %v", cmd.String(), err)
	}

	if err = endpoint.AddRoute("10.0.0.0/8"); err != nil {
		log.Printf("Run AddRoute 10.0.0.0/8 failed: %v", err)
	}

	cmd = exec.Command("ifconfig", ifce.Name(), "mtu", "1400", "up")
	err = cmd.Run()
	if err != nil {
		log.Printf("Run %s failed: %v", cmd.String(), err)
	}
}
