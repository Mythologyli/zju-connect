package log

// Redact keeps the first and last characters of a secret, so a log line can say
// which secret it is about and how long it is, without printing it.
func Redact(secret string) string {
	if secret == "" {
		return ""
	}
	if len(secret) <= 8 {
		return "***"
	}
	return secret[:4] + "…" + secret[len(secret)-4:]
}
