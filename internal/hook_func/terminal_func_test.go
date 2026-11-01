package hook_func

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestFatalfReleasesResourcesBeforeExiting: a fatal path must run the terminal
// functions (TUN device, routes, listeners) before the process goes away.
func TestFatalfReleasesResourcesBeforeExiting(t *testing.T) {
	if os.Getenv("ZJU_CONNECT_TEST_FATAL") != "" {
		RegisterTerminalFunc("test-release", func(context.Context) error {
			fmt.Println("released")
			return nil
		})
		Fatalf("fatal: %s", "boom")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestFatalfReleasesResourcesBeforeExiting$")
	cmd.Env = append(os.Environ(), "ZJU_CONNECT_TEST_FATAL=1")
	output, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("exit = %v, want status 1 (output: %s)", err, output)
	}
	if !strings.Contains(string(output), "released") {
		t.Fatalf("the terminal functions did not run before the exit: %s", output)
	}
	if !strings.Contains(string(output), "fatal: boom") {
		t.Fatalf("the message was not printed: %s", output)
	}
}
