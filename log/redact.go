package log

import "regexp"

// secretJSONFieldPattern matches the response fields that carry session material.
// A debug dump is not a place for a credential: these are the fields the gateway
// hands back for the restore path, and every one of them is a bearer secret.
var secretJSONFieldPattern = regexp.MustCompile(
	`"(ticket|sidTicket|sid|sid\.sig|sid-legacy|sid-legacy\.sig|straceid|straceid\.sig|sign_key|signKey)"\s*:\s*"[^"]*"`)

// RedactSecrets masks the value of every session-material field in a payload, so a
// debug dump can show the shape of a response without carrying the credential.
// It is a text filter, not a JSON parser, and it is deliberately greedy: a field
// it misses is a leaked credential.
func RedactSecrets(payload string) string {
	return secretJSONFieldPattern.ReplaceAllString(payload, `"$1":"***"`)
}

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
