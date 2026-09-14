package wallet

import "github.com/trustknots/vcknots/wallet/common"

// CodedError is the interface every error this library returns from a public
// API satisfies: it names the condition it reports with a stable,
// machine-readable code, so an integrator can branch on the condition — or
// carry it across a process, transport or language boundary — without matching
// Go error text.
//
// The codes are lower_snake_case ASCII, unique across the library, and part of
// its public contract: a message may be reworded, a code may not be reused for
// another condition.
type CodedError = common.CodedError

// ErrorCode reports the stable code of the outermost CodedError in err's chain,
// and whether one was found. An error this library did not classify returns
// ("", false), which lets a caller keep its own fallback rather than report a
// verdict the library did not reach.
//
// The outermost code wins because an error that wraps another and still names a
// code has classified what it wraps.
func ErrorCode(err error) (string, bool) {
	return common.CodeOf(err)
}
