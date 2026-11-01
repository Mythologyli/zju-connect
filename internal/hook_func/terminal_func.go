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

// Fatalf releases what the terminal functions own, then exits. A genuine fatal
// path (a stack that cannot be built, a certificate that cannot be read) must not
// leave the TUN device and its routes behind. A session that merely died is not a
// genuine fatal path: the recovery ladder handles that without exiting.
func Fatalf(format string, v ...any) {
	if errs := ExecTerminalFunc(context.Background()); errs != nil {
		for _, err := range errs {
			log.Println("Cleanup before exit failed:", err)
		}
	}
	log.Fatalf(format, v...)
}

func IsTerminal() bool {
	terminalMu.Lock()
	defer terminalMu.Unlock()

	return terminalBegin
}
