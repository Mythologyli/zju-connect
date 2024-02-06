package hook_func

import (
	"context"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/log"
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
