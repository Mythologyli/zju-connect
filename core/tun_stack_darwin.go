package core

import (
	"golang.zx2c4.com/wireguard/tun"
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
	tun.CreateTUN("zjuconnect", 0)

	endpoint.dev = dev
}
