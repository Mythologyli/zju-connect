package hook_func

import (
	"context"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/log"
	"os/user"
)

func init() {
	RegisterInitialFunc("check tun mode cap", func(ctx context.Context, config configs.Config) error {
		// discard error
		if config.TUNMode {
			current, _ := user.Current()
			if current.Uid != "0" {
				log.Println("检测到TUN模式，但是当前用户不是root，可能会导致无法使用，如果遇到问题请使用sudo运行")
			}
		}
		return nil
	})
	RegisterInitialFunc("check bind port", checkBindPortLegal)
}
