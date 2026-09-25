package oid4vci

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// A Challenge an authorization server provided is kept per server and per
// Client Instance Key: it is never presented with another key, which would
// link the keys, and the caller's own Challenge from the challenge endpoint
// takes precedence as the most recently received one.
func TestAttestationChallengeIsKeptPerServerAndKey(t *testing.T) {
	origin := url.URL{Scheme: "https", Host: "as.example"}
	prover := func(thumbprint, challenge string) exchange {
		return exchange{url: origin, attestation: types.ClientAttestationProver{
			KeyThumbprint: thumbprint,
			Challenge:     challenge,
			Headers: func(string) (types.OAuthClientAttestationHeaders, error) {
				return types.OAuthClientAttestationHeaders{}, nil
			},
		}}
	}
	receiver := &Oid4vciReceiver{}
	header := http.Header{}
	header.Set(attestationChallengeHeader, "challenge-a")
	receiver.rememberAttestationChallenge(prover("key-a", ""), header)

	if got := receiver.attestationChallengeFor(prover("key-a", "")); got != "challenge-a" {
		t.Fatalf("same key: %q", got)
	}
	if got := receiver.attestationChallengeFor(prover("key-b", "")); got != "" {
		t.Fatalf("a Challenge kept for key-a reached key-b: %q", got)
	}
	other := prover("key-a", "")
	other.url = url.URL{Scheme: "https", Host: "other-as.example"}
	if got := receiver.attestationChallengeFor(other); got != "" {
		t.Fatalf("a Challenge reached another server: %q", got)
	}
	if got := receiver.attestationChallengeFor(prover("key-a", "from-endpoint")); got != "from-endpoint" {
		t.Fatalf("the challenge endpoint's Challenge did not take precedence: %q", got)
	}
	if got := receiver.attestationChallengeFor(prover("", "")); got != "" {
		t.Fatalf("a prover without a key thumbprint got a kept Challenge: %q", got)
	}
}
