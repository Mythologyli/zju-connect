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
	command := exec.Command("ip", "route", "add", target, "dev", ep.ifce.Name())
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

	cmd := exec.Command("ip", "link", "set", ifce.Name(), "up")
	err = cmd.Run()
	if err != nil {
		log.Printf("Run %s failed: %v", cmd.String(), err)
	}

	cmd = exec.Command("ip", "addr", "add", fmt.Sprintf("%d.%d.%d.%d/8", ip[0], ip[1], ip[2], ip[3]), "dev", ifce.Name())
	err = cmd.Run()
	if err != nil {
		log.Printf("Run %s failed: %v", cmd.String(), err)
	}
}
