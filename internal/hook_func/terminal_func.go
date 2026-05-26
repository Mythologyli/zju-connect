package hook_func

import (
	"context"
	"sync"

	"github.com/mythologyli/zju-connect/log"
)

type TerminalFunc func(ctx context.Context) error
type TerminalItem struct {
	f    TerminalFunc
	name string
}

var terminalFuncList []TerminalItem

var terminalBegin = false
var terminalMu sync.Mutex

func RegisterTerminalFunc(execName string, fun TerminalFunc) {
	terminalMu.Lock()
	defer terminalMu.Unlock()

	if terminalBegin {
		log.Println("Terminal already started, skip registering func:", execName)
		return
	}

	terminalFuncList = append(terminalFuncList, TerminalItem{
		f:    fun,
		name: execName,
	})
	log.Println("Register func on terminal:", execName)
}

func ExecTerminalFunc(ctx context.Context) []error {
	terminalMu.Lock()
	if terminalBegin {
		terminalMu.Unlock()
		return nil
	}
	terminalBegin = true
	funcList := append([]TerminalItem(nil), terminalFuncList...)
	terminalMu.Unlock()

	var errList []error
	for _, item := range funcList {
		log.Println("Exec func on terminal:", item.name)
		if err := item.f(ctx); err != nil {
			errList = append(errList, err)
			log.Println("Exec func on terminal ", item.name, "failed:", err)
		} else {
			log.Println("Exec func on terminal ", item.name, "success")
		}
	}
	return errList
}

func IsTerminal() bool {
	terminalMu.Lock()
	defer terminalMu.Unlock()

	return terminalBegin
}
