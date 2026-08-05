package atrust

import "testing"

func TestNormalizePolicyDomainPreservesWildcardBoundary(t *testing.T) {
	if got := normalizePolicyDomain("*.example.com"); got != ".example.com" {
		t.Fatalf("wildcard domain = %q", got)
	}
	if got := normalizePolicyDomain("api.*.example.com"); got != "" {
		t.Fatalf("unsupported wildcard domain = %q, want empty", got)
	}
}
