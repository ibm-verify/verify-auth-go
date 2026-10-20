// Package auth provides shared types for the IBM Verify auth SDK.
package auth

import (
	"fmt"
	"strings"
)

// Error represents an error originating either from an authorization server
// (AS) or from within the SDK itself.
//
// AS errors map the OAuth 2.0 error response fields directly:
//
//	Code        ← "error"             (e.g. "invalid_grant")
//	Description ← "error_description" (e.g. "Token has expired")
//
// SDK errors use their own code namespace (snake_case verbs, no collision
// with AS error codes defined in RFC 6749 / RFC 8628 etc.):
//
//	Code        ← e.g. "state_mismatch", "jwks_fetch_failed", "token_expired"
//	Description ← human-readable detail
//	Args        ← structured context for programmatic inspection
//	Cause       ← wrapped upstream error (accessible via errors.Is / errors.As)
type Error struct {
	// Code is the error code. For AS errors this is the OAuth 2.0 "error"
	// field. For SDK errors this is a snake_case identifier.
	Code string

	// Description is a human-readable explanation of the error. For AS errors
	// this is the OAuth 2.0 "error_description" field.
	Description string

	// Args holds structured context about the error for programmatic
	// inspection (e.g. {"status_code": 401, "issuer": "https://..."}).
	// It is nil for errors that carry no additional context.
	Args map[string]any

	// Cause is the underlying error that triggered this Error, if any.
	// Use errors.Is / errors.As to inspect the chain.
	Cause error
}

// Error implements the error interface.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.Code)
	if e.Description != "" {
		b.WriteString(": ")
		b.WriteString(e.Description)
	}
	if len(e.Args) > 0 {
		b.WriteString(" (")
		first := true
		for k, v := range e.Args {
			if !first {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s=%v", k, v)
			first = false
		}
		b.WriteByte(')')
	}
	if e.Cause != nil {
		b.WriteString(": ")
		b.WriteString(e.Cause.Error())
	}
	return b.String()
}

// Unwrap returns the underlying cause so errors.Is / errors.As work correctly.
func (e *Error) Unwrap() error {
	return e.Cause
}
