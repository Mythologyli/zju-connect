package atrust

import (
	"fmt"
	"testing"
)

func TestIsAuthTimeoutErr(t *testing.T) {
	err := fmt.Errorf("%w for 4:<client-ip>:<client-port>-<dns-server>:53", errL3TunnelAuthTimeout)
	if !isAuthTimeoutErr(err) {
		t.Fatal("expected wrapped l3 tunnel auth timeout to be recognized")
	}

	if isAuthTimeoutErr(nil) {
		t.Fatal("nil error must not be treated as auth timeout")
	}

	if isAuthTimeoutErr(fmt.Errorf("l3-tunnel auth timeout for unrelated text")) {
		t.Fatal("plain text error must not be treated as auth timeout")
	}
}
