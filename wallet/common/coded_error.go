package common

import "errors"

// CodedError is an error that names the condition it reports with a stable,
// machine-readable code. The code is part of the library's public contract: it
// survives a reword of the message, crosses a process or language boundary
// unchanged, and lets an integrator branch on a condition without importing the
// package that declared it or matching Go error text.
//
// The method is ErrorCode rather than Code because several of the errors that
// implement it already carry a protocol `error` code in a field named Code —
// *types.CredentialEndpointError, *oid4vp.AuthorizationRequestError and
// *wallet.AuthorizationResponseError — and those two values are not the same
// thing: the field is what the peer sent, ErrorCode is what this library
// concluded.
//
// Codes are lower_snake_case ASCII and unique across the library.
type CodedError interface {
	error
	// ErrorCode returns the stable code of this condition.
	ErrorCode() string
}

// codedError is a sentinel that carries a code alongside its message. It is a
// pointer type, so a package-level value built by NewCodedError compares by
// identity exactly as an errors.New sentinel does and keeps working with
// errors.Is.
type codedError struct {
	code    string
	message string
}

func (e *codedError) Error() string { return e.message }

func (e *codedError) ErrorCode() string { return e.code }

// NewCodedError returns a sentinel error reporting message that names its
// condition with code. It is the CodedError counterpart of errors.New.
func NewCodedError(code, message string) error {
	return &codedError{code: code, message: message}
}

// WrapCoded returns an error that reports message, keeps cause in the chain for
// errors.Is and errors.As, and names its condition with code. It is the
// counterpart of fmt.Errorf("...: %w", cause) for a wrapper that classifies.
func WrapCoded(code, message string, cause error) error {
	if cause == nil {
		return NewCodedError(code, message)
	}
	return &wrappedCodedError{codedError: codedError{code: code, message: message}, cause: cause}
}

type wrappedCodedError struct {
	codedError
	cause error
}

func (e *wrappedCodedError) Unwrap() error { return e.cause }

// CodeOf reports the stable code of the outermost CodedError in err's chain.
// The outermost one wins because an error that wraps another and still names a
// code has classified what it wraps: *x509.SigningChainError defers to the
// *x509.CRLCheckError underneath it for exactly that reason.
func CodeOf(err error) (string, bool) {
	var coded CodedError
	if !errors.As(err, &coded) {
		return "", false
	}
	return coded.ErrorCode(), true
}
