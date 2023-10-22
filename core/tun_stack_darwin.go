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

func SetupTunStack(ip []byte, endpoint *EasyConnectTunEndpoint) {
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Interface Name: %s\n", ifce.Name())

	endpoint.ifce = ifce

	cmd := exec.Command("/sbin/ifconfig", ifce.Name(), fmt.Sprintf("%d.%d.%d.%d/8", ip[0], ip[1], ip[2], ip[3]), "up")
	err = cmd.Run()
	if err != nil {
		log.Printf("Run ifconfig failed: %v", err)
	}
}
