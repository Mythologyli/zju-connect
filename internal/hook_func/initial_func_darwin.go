package hook_func

import (
	"context"
	"os"
)

func init() {
	RegisterInitialFunc("clean resolver file", func(ctx context.Context) error {
		// discard error
		_ = os.Remove("/etc/resolver/zju.edu.cn")
		_ = os.Remove("/etc/resolver/cc98.org")
		return nil
	})
}
