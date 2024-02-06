package hook_func

import (
	"context"
	"errors"
	"github.com/mythologyli/zju-connect/configs"
	"os"
	"os/user"
)

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
}
