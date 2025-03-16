package hook_func

import (
	"context"
	"errors"
	"fmt"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/log"
	netstat "github.com/shirou/gopsutil/v4/net"
	"net"
)

type InitialFunc func(ctx context.Context, config configs.Config) error
type InitialItem struct {
	f    InitialFunc
	name string
}

var initialFuncList []InitialItem

var initialEnd = false

func RegisterInitialFunc(execName string, fun InitialFunc) {
	initialFuncList = append(initialFuncList, InitialItem{
		f:    fun,
		name: execName,
	})
}

func ExecInitialFunc(ctx context.Context, config configs.Config) []error {
	var errList []error
	for _, item := range initialFuncList {
		log.Println("Exec func on initial:", item.name)
		if err := item.f(ctx, config); err != nil {
			errList = append(errList, err)
			log.Println("Exec func on initial ", item.name, "failed:", err)
		} else {
			log.Println("Exec func on initial ", item.name, "success")
		}
	}
	initialEnd = true
	return errList
}

func IsInitial() bool {
	return initialEnd
}

func checkBindPortLegal(ctx context.Context, config configs.Config) error {
	var checkTCPPorts, checkUDPPorts []uint32
	checkTCPPortsStr := []string{config.HTTPBind, config.SocksBind}
	checkUDPPortsStr := []string{config.DNSServerBind}

	for _, addrStr := range checkTCPPortsStr {
		if len(addrStr) != 0 {
			addr, err := net.ResolveTCPAddr("tcp", addrStr)
			if err != nil || addr.Port == 0 {
				return errors.New(fmt.Sprintf("配置项中 %s 填写错误，请参考Readme中填写", addr))
			}
			checkTCPPorts = append(checkTCPPorts, uint32(addr.Port))
		}
	}

	for _, addrStr := range checkUDPPortsStr {
		if len(addrStr) != 0 {
			addr, err := net.ResolveUDPAddr("udp", addrStr)
			if err != nil || addr.Port == 0 {
				return errors.New(fmt.Sprintf("配置项中 %s 填写错误，请参考Readme中填写", addr))
			}
			checkUDPPorts = append(checkUDPPorts, uint32(addr.Port))
		}
	}

	for _, kind := range []string{"tcp", "udp"} {
		connectionStats, err := netstat.Connections(kind)
		if err != nil {
			// skip this check due to lack of information
			return nil
		}
		var targetCheckPorts []uint32
		if kind == "tcp" {
			targetCheckPorts = checkTCPPorts
		} else {
			targetCheckPorts = checkUDPPorts
		}
		for _, conn := range connectionStats {
			for _, checkPort := range targetCheckPorts {
				// darwin "*" means "0.0.0.0"
				if checkPort == conn.Laddr.Port && (conn.Laddr.IP == "::" || conn.Laddr.IP == "*" ||
					conn.Laddr.IP == "0.0.0.0" || conn.Laddr.IP == "127.0.0.1") {
					return errors.New(fmt.Sprintf("%s端口%s已经被进程%d占用，请更换端口或结束占用该端口的进程", kind, conn.Laddr.String(), conn.Pid))
				}
			}
		}
	}
	return nil
}
