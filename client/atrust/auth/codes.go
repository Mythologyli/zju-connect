package auth

import (
	"errors"
	"fmt"
)

const (
	// The codes the session and restore paths need to tell apart. Keeping the
	// numbers in one place is what makes the classification testable: a caller
	// reads CodeFromError instead of matching message text.
	codeSessionNotFound      = 10000004
	codeSessionTimeout       = 75500001
	codeSessionInvalid       = 75500002
	codeAccountStillOnline   = 75500006
	codeStaleTicket          = 75500304
	codeStaleRandomCheckCode = 75500307
)

// sessionDeathCodes are the portal codes that mean the session is gone;
// 75500001 is the timeout variant of 75500002.
var sessionDeathCodes = map[int]bool{
	codeSessionNotFound: true,
	codeSessionTimeout:  true,
	codeSessionInvalid:  true,
}

// IsSessionDeathCode reports whether a portal code means the session is gone.
func IsSessionDeathCode(code int) bool {
	return sessionDeathCodes[code]
}

// PortalCodeError is a non-zero portal business code. The code is a field, so a
// caller classifies the answer without parsing the message text; Kind carries the
// sentinel the caller reacts to (ErrSessionInvalid, ErrStaleTicket).
type PortalCodeError struct {
	Op      string
	Code    int
	Message string
	Kind    error
	Note    string
}

func (e *PortalCodeError) Error() string {
	message := fmt.Sprintf("%s failed with code %d", e.Op, e.Code)
	if e.Message != "" {
		message += " (" + e.Message + ")"
	}
	if e.Note != "" {
		message += ": " + e.Note
	}
	if e.Kind != nil {
		return e.Kind.Error() + ": " + message
	}
	return message
}

func (e *PortalCodeError) Unwrap() error { return e.Kind }

// CodeFromError returns the portal business code carried by err, if any.
func CodeFromError(err error) (int, bool) {
	var coded *PortalCodeError
	if errors.As(err, &coded) {
		return coded.Code, true
	}
	return 0, false
}

// ticketError classifies a non-zero portal code on the restore and re-login path,
// so the ladder can tell "mint a new ticket", "the session is gone" and "the
// portal refused for another reason" apart instead of treating every answer as
// fatal.
func ticketError(step string, code int, message string) error {
	coded := &PortalCodeError{Op: step, Code: code, Message: message}
	switch {
	case IsSessionDeathCode(code):
		coded.Kind = ErrSessionInvalid
	case code == codeStaleTicket:
		// The stored ticket is no good any more.
		coded.Kind = ErrStaleTicket
	case code == codeStaleRandomCheckCode:
		// The random check code is only valid while logged in: the ticket source
		// needs a live session, so a new ticket has to be minted rather than the
		// same call retried.
		coded.Kind = ErrStaleTicket
	case code == codeAccountStillOnline:
		// The account is still online server-side (about 24 minutes after a
		// client-side logout) and a fresh login is refused meanwhile. That is
		// neither a wrong credential nor a reason to exit.
		coded.Note = "the account is still online, retry later"
	}
	return coded
}
