package hook_func

import (
	"context"
	"os/user"

	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/log"
)

func init() {
	RegisterInitialFunc("check tun mode cap", func(ctx context.Context, config configs.Config) error {
		// discard error
		if config.TUNMode {
			current, _ := user.Current()
			if current.Uid != "0" {
				log.Println("TUN mode detected, but the current user is not root. This may cause issues. If you encounter problems, please run the application using sudo.")
			}
		}
		return nil
	})
	RegisterInitialFunc("check bind port", checkBindPortLegal)
}
