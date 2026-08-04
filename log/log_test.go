package log

import (
	"bytes"
	stdlog "log"
	"strings"
	"testing"
)

func TestDebugPrintfHonorsEnabledState(t *testing.T) {
	var output bytes.Buffer
	previous := stdlog.Writer()
	stdlog.SetOutput(&output)
	t.Cleanup(func() {
		DisableDebug()
		stdlog.SetOutput(previous)
	})

	DisableDebug()
	DebugPrintf("hidden %d", 1)
	if output.Len() != 0 {
		t.Fatalf("disabled debug output = %q, want empty", output.String())
	}

	EnableDebug()
	DebugPrintf("visible %d", 2)
	if !strings.Contains(output.String(), "visible 2") {
		t.Fatalf("enabled debug output = %q, want visible message", output.String())
	}
}
