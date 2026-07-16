//go:build windows

package underlay

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

func bindInterface(dialer *net.Dialer, interfaceName string) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	dialer.ControlContext = func(_ context.Context, network, _ string, conn syscall.RawConn) error {
		var bindErr error
		err := conn.Control(func(fd uintptr) {
			handle := syscall.Handle(fd)
			if strings.HasSuffix(network, "6") {
				bindErr = syscall.SetsockoptInt(handle, syscall.IPPROTO_IPV6, ipv6UnicastIf, iface.Index)
				return
			}
			var bytes [4]byte
			binary.BigEndian.PutUint32(bytes[:], uint32(iface.Index))
			index := *(*uint32)(unsafe.Pointer(&bytes[0]))
			bindErr = syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, ipUnicastIf, int(index))
		})
		if err != nil {
			return err
		}
		return bindErr
	}
	return nil
}
