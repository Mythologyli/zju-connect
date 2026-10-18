package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/mythologyli/zju-connect/internal/hook_func"
)

// TestSocksListenFailureRunsTerminalFuncs: a port that is already in use must not
// panic out of the listener goroutine (which skips the cleanup hooks and leaks the
// TUN device and routes). It must run the terminal functions and exit non-zero.
func TestSocksListenFailureRunsTerminalFuncs(t *testing.T) {
	if os.Getenv("ZJU_CONNECT_TEST_SOCKS_FATAL") != "" {
		hook_func.RegisterTerminalFunc("test-release", func(context.Context) error {
			fmt.Println("released")
			return nil
		})

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()

		ServeSocks5(listener.Addr().String(), nil, nil, "", "")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestSocksListenFailureRunsTerminalFuncs$")
	cmd.Env = append(os.Environ(), "ZJU_CONNECT_TEST_SOCKS_FATAL=1")
	output, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("exit = %v, want status 1 (output: %s)", err, output)
	}
	if !strings.Contains(string(output), "released") {
		t.Fatalf("the terminal functions did not run before the exit: %s", output)
	}
	if !strings.Contains(string(output), "SOCKS5 listen failed") {
		t.Fatalf("the bind failure was not reported: %s", output)
	}
}
