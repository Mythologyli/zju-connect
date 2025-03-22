package hook_func

import (
	"bytes"
	"context"
	"errors"
	"github.com/mythologyli/zju-connect/configs"
	"os"
	"os/exec"
	"os/user"
	"strings"
)

// get all services and skip element contains "*"
func ListNetworkServices() ([]string, error) {
	cmd := exec.Command("networksetup", "-listallnetworkservices")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var services []string
	for _, line := range lines[1:] { // 跳过第一行标题
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "*") {
			services = append(services, line)
		}
	}
	return services, nil
}

func SetDNSServer(service, dns string) error {
	cmd := exec.Command("networksetup", "-setdnsservers", service, dns)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	return cmd.Run()
}

func SetDNSServerWithHook(service, dns string) error {
	// networksetup -setdnsservers "service name" DNS_IP
	cmd := exec.Command("networksetup", "-setdnsservers", service, dns)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	RegisterTerminalFunc("CleanDnsServer_"+service, func(ctx context.Context) error {
		delCommand := exec.Command("networksetup", "-setdnsservers", service, "Empty")
		delErr := delCommand.Run()
		if delErr != nil {
			return delErr
		}
		return nil
	})

	return nil
}

func init() {
	RegisterInitialFunc("clean resolver file", func(ctx context.Context, config configs.Config) error {
		// discard error
		_ = os.Remove("/etc/resolver/zju.edu.cn")
		_ = os.Remove("/etc/resolver/cc98.org")
		return nil
	})
	RegisterInitialFunc("check tun mode cap", func(ctx context.Context, config configs.Config) error {
		// discard error
		if config.TUNMode {
			current, _ := user.Current()
			if current.Uid != "0" {
				return errors.New("请使用sudo运行TUN模式")
			}
		}
		return nil
	})
	RegisterInitialFunc("check bind port", checkBindPortLegal)
	RegisterInitialFunc("set dns server", func(ctx context.Context, config configs.Config) error {
		services, err := ListNetworkServices()
		if err != nil {
			return err
		}

		for _, service := range services {
			if err := SetDNSServer(service, "Empty"); err != nil {
				return err
			}
		}
		return nil
	})

}
