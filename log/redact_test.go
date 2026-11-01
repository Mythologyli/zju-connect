package log

import "testing"

func TestRedactSecrets(t *testing.T) {
	for _, tt := range []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "the renewal ticket",
			payload: `{"code":0,"data":{"ticket":"auth-config-ticket","csrfToken":"csrf-1"}}`,
			want:    `{"code":0,"data":{"ticket":"***","csrfToken":"csrf-1"}}`,
		},
		{
			name:    "the restore ticket",
			payload: `{"code":0,"data":{"sidTicket":"` + "73chars" + `"},"message":"成功"}`,
			want:    `{"code":0,"data":{"sidTicket":"***"},"message":"成功"}`,
		},
		{
			name:    "the cookie family",
			payload: `{"sid":"abc","sid.sig":"def","straceid":"ghi","username":"student"}`,
			want:    `{"sid":"***","sid.sig":"***","straceid":"***","username":"student"}`,
		},
		{
			name:    "a payload without secrets is left alone",
			payload: `{"code":75500002,"message":"会话无效"}`,
			want:    `{"code":75500002,"message":"会话无效"}`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactSecrets(tt.payload); got != tt.want {
				t.Fatalf("RedactSecrets(%s) = %s, want %s", tt.payload, got, tt.want)
			}
		})
	}
}

func TestRedact(t *testing.T) {
	if got := Redact(""); got != "" {
		t.Fatalf("Redact(empty) = %q, want an empty string", got)
	}
	if got := Redact("short"); got != "***" {
		t.Fatalf("Redact(short) = %q, want the whole value hidden", got)
	}
	if got := Redact("0123456789abcdef"); got != "0123…cdef" {
		t.Fatalf("Redact() = %q, want the ends only", got)
	}
}
