package log

import "testing"

func TestRedactKeepsOnlyTheEdges(t *testing.T) {
	for _, tt := range []struct {
		name   string
		secret string
		want   string
	}{
		{"empty", "", ""},
		{"short", "secret", "***"},
		{"eight characters", "12345678", "***"},
		{"longer", "0123456789abcdef", "0123…cdef"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Redact(tt.secret); got != tt.want {
				t.Fatalf("Redact(%q) = %q, want %q", tt.secret, got, tt.want)
			}
		})
	}
}
