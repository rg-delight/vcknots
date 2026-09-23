package wallet

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/common/observe"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// oid4vciFinalFlow is the part of an in-flight Final issuance that is not
// serialisable: the receiver plugin, the holder keys and the signing decisions
// taken from the wallet configuration. Begin builds it; Resume rebuilds it from
// the request and the persisted OID4VCIFinalAuthorization.
type oid4vciFinalFlow struct {
	receiver                    receiverTypes.OID4VCIFinalTransport
	signer                      receiverTypes.OID4VCIFinalSigner
	issuerMetadata              *receiverTypes.CredentialIssuerMetadata
	authorizationServerMetadata *receiverTypes.AuthorizationServerMetadata
	authorizationServerIssuer   string
	credentialConfigurationID   string
	credentialConfiguration     receiverTypes.CredentialConfiguration
	// authorizationDetailsMode is how the authorization request asked for the
	// configuration (OpenID4VCI 1.0 §5.1.1/§5.1.2), derived by
	// newOID4VCIFinalFlow from oid4vciAuthorizationRequestParameters so the
	// Token Response can be judged against the request that produced it.
	authorizationDetailsMode AuthorizationDetailsMode
	holderKeys               []jose.JSONWebKey
	keyAttestation           *oid4vciKeyAttestationPlan
	// suppliedKeyAttestation is an Appendix D key attestation the caller minted
	// out of process for suppliedKeyAttestationNonce. When it is set the flow
	// never calls a provider: it embeds this attestation, and a Credential
	// Endpoint that answers §8.3.1.2 "invalid_nonce" makes the flow stop with
	// ErrKeyAttestationNonceStale instead, because the caller has to sign the
	// fresh c_nonce itself.
	suppliedKeyAttestation      *KeyAttestation
	suppliedKeyAttestationNonce string
	usePrivateKeyJwt            bool
	generateClientAssertion     func() (string, error)
	// policy is the Holder's own §8 credential request policy, carried on the
	// flow so the immediate and the §9 deferred paths apply the same one.
	policy oid4vciFinalCredentialPolicy
}

// oid4vciFinalCredentialPolicy collects the Holder-owned switches of the §8
// Credential Request that the OpenID4VCI 1.0 metadata cannot express.
type oid4vciFinalCredentialPolicy struct {
	encryption              CredentialEncryptionPolicy
	skipNotification        bool
	requireSingleCredential bool
}

// ReceiveOID4VCIFinalCredential implements the OpenID4VCI 1.0 Final/HAIP
// authorization-code credential issuance flow. It is
// ReceiveOID4VCIFinalCredentialContext with a background context.
func (w *Wallet) ReceiveOID4VCIFinalCredential(req OID4VCIFinalReceiveRequest) (*OID4VCIFinalReceiveResult, error) {
	return w.ReceiveOID4VCIFinalCredentialContext(context.Background(), req)
}

// ReceiveOID4VCIFinalCredentialContext runs the whole OpenID4VCI 1.0 Final/HAIP
// authorization-code flow in one call, including the §5.2 authorization
// endpoint. Driving the authorization endpoint from the wallet process only
// works against an issuer that answers the bare GET with a redirect carrying
// the code, so it is gated behind
// OID4VCIFinalReceiveRequest.AllowSelfDrivenAuthorization; a wallet with a user
// calls BeginOID4VCIFinalAuthorization and ResumeOID4VCIFinalAuthorization
// around a system browser instead.
//
// ctx bounds every request the flow makes and cancels deferred credential
// polling.
func (w *Wallet) ReceiveOID4VCIFinalCredentialContext(ctx context.Context, req OID4VCIFinalReceiveRequest) (*OID4VCIFinalReceiveResult, error) {
	if err := validateOID4VCIFinalReceiveRequest(req); err != nil {
		return nil, err
	}
	if !req.AllowSelfDrivenAuthorization {
		// Checked before anything is sent, so a caller that has to migrate does
		// not first consume a pushed authorization request_uri.
		return nil, fmt.Errorf("the authorization code flow requires a browser: use BeginOID4VCIFinalAuthorization, or set AllowSelfDrivenAuthorization for a test issuer")
	}
	authorization, flow, err := w.beginOID4VCIFinalAuthorization(ctx, req)
	if err != nil {
		return nil, err
	}
	redirectURL, err := followOID4VCIAuthorizationEndpoint(req.HTTPClient, authorization)
	if err != nil {
		return nil, err
	}
	return w.resumeOID4VCIFinalAuthorization(ctx, req, authorization, flow, redirectURL)
}

// BeginOID4VCIFinalAuthorization performs everything the OpenID4VCI 1.0 §5
// authorization code flow does before the user agent is involved: it resolves
// the issuer and authorization server metadata, validates the selected
// Credential Configuration, pushes the authorization request when the flow uses
// RFC 9126 PAR, and returns the authorization URL to open in a browser together
// with the state the caller must hand back to
// ResumeOID4VCIFinalAuthorization.
func (w *Wallet) BeginOID4VCIFinalAuthorization(ctx context.Context, req OID4VCIFinalReceiveRequest) (*OID4VCIFinalAuthorization, error) {
	authorization, _, err := w.beginOID4VCIFinalAuthorization(ctx, req)
	if err != nil {
		return nil, err
	}
	return authorization, nil
}

// ResumeOID4VCIFinalAuthorization continues the flow from the redirect the
// browser delivered to the wallet's registered redirect_uri. It validates the
// RFC 6749 §4.1.2 / RFC 9207 authorization response against auth, exchanges the
// code at the token endpoint and performs the §8 credential request. req must
// carry the same client, redirect_uri and holder keys the matching
// BeginOID4VCIFinalAuthorization call used.
func (w *Wallet) ResumeOID4VCIFinalAuthorization(ctx context.Context, req OID4VCIFinalReceiveRequest, auth *OID4VCIFinalAuthorization, redirectURL string) (*OID4VCIFinalReceiveResult, error) {
	if auth == nil {
		return nil, fmt.Errorf("authorization state is required")
	}
	flow, err := w.restoreOID4VCIFinalFlow(req, auth)
	if err != nil {
		return nil, err
	}
	return w.resumeOID4VCIFinalAuthorization(ctx, req, auth, flow, redirectURL)
}

// requireOID4VCIContext reports a cancelled context at an issuance step
// boundary, naming the step that was about to start.
//
// It is not what stops a request in flight: every OID4VCIFinalTransport method
// that performs I/O now takes the flow context and binds its HTTP requests to
// it, so cancelling ctx aborts the request that is running. This check adds the
// part a bound request cannot give: it stops the flow between steps, before any
// key proof, DPoP proof, client assertion or key attestation is signed for a
// request that would be abandoned anyway, and it names the step in the error
// instead of surfacing a bare transport failure.
func requireOID4VCIContext(ctx context.Context, step string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("OpenID4VCI issuance cancelled before %s: %w", step, err)
	}
	return nil
}

// restoreOID4VCIFinalFlow rebuilds the non-serialisable half of an issuance
// from the request and the persisted authorization state. The issuer and
// authorization server metadata come from the state, not from a fresh fetch, so
// a restarted wallet continues against exactly the metadata the authorization
// request was built from.
func (w *Wallet) restoreOID4VCIFinalFlow(req OID4VCIFinalReceiveRequest, auth *OID4VCIFinalAuthorization) (*oid4vciFinalFlow, error) {
	if err := validateOID4VCIFinalReceiveRequest(req); err != nil {
		return nil, err
	}
	if auth.IssuerMetadata == nil {
		return nil, fmt.Errorf("authorization state is missing the issuer metadata")
	}
	if auth.AuthorizationServerMetadata == nil {
		return nil, fmt.Errorf("authorization state is missing the authorization server metadata")
	}
	if auth.AuthorizationServerMetadata.TokenEndpoint == nil {
		return nil, fmt.Errorf("token endpoint is missing on authorization server")
	}
	finalReceiver, err := w.receiver.OID4VCIFinalTransport(req.Type)
	if err != nil {
		return nil, fmt.Errorf("OID4VCI Final receiver capability is not available: %w", err)
	}
	return w.newOID4VCIFinalFlow(req, finalReceiver, auth.IssuerMetadata, auth.AuthorizationServerMetadata, auth.CredentialConfigurationID, true)
}

// resumeOID4VCIFinalAuthorization is the composition of the two halves of the
// resumed flow: authorizeOID4VCIFinalToken exchanges the code and collects
// everything the Credential Request needs into an OID4VCIFinalTokenGrant, and
// requestOID4VCIFinalCredentials spends it. Both halves see the same flow, so
// running them back to back is exactly what the single call did before they
// were separable.
func (w *Wallet) resumeOID4VCIFinalAuthorization(
	ctx context.Context,
	req OID4VCIFinalReceiveRequest,
	auth *OID4VCIFinalAuthorization,
	flow *oid4vciFinalFlow,
	redirectURL string,
) (*OID4VCIFinalReceiveResult, error) {
	grant, err := w.authorizeOID4VCIFinalToken(ctx, req, auth, flow, redirectURL)
	if err != nil {
		return nil, err
	}
	return w.requestOID4VCIFinalCredentials(ctx, flow, grant, req.ClientKey, req.CredentialResponseEncryptionKey, req.DeferredPollAttempts, req.MaxDeferredInterval)
}

// authorizeOID4VCIFinalToken performs everything between the browser redirect
// and the Credential Request: the RFC 6749 §4.1.2 / RFC 9207 §2.4 checks on the
// redirect, the §6.1 token exchange, the §6.2 credential_identifier selection
// and the §7 c_nonce fetch.
func (w *Wallet) authorizeOID4VCIFinalToken(
	ctx context.Context,
	req OID4VCIFinalReceiveRequest,
	auth *OID4VCIFinalAuthorization,
	flow *oid4vciFinalFlow,
	redirectURL string,
) (*OID4VCIFinalTokenGrant, error) {
	code, err := validateOID4VCIAuthorizationRedirect(redirectURL, auth.AuthorizationURL, auth.State, req.RedirectURI, flow.issuerPolicy(w.profile.IsHAIP()))
	if err != nil {
		return nil, err
	}

	if err := requireOID4VCIContext(ctx, "the token request"); err != nil {
		return nil, err
	}
	attestationHeaders, attestationChallenge, err := w.createOID4VCIAttestationHeaders(ctx, flow.receiver, req, flow.authorizationServerMetadata, flow.authorizationServerIssuer)
	if err != nil {
		return nil, err
	}

	tokenRequest := receiverTypes.AuthorizationCodeTokenRequest{
		Code:         code,
		RedirectURI:  req.RedirectURI,
		CodeVerifier: auth.CodeVerifier,
		ClientID:     req.ClientID,
	}
	if flow.usePrivateKeyJwt {
		// The factory is invoked once per HTTP attempt, so a DPoP nonce retry
		// re-sends the token request with a fresh client_assertion (new jti)
		// rather than replaying the first one.
		tokenRequest.ClientAssertionType = receiverTypes.ClientAssertionTypeJWTBearer
		tokenRequest.ClientAssertionFactory = flow.generateClientAssertion
	}
	token, err := flow.receiver.ExchangeAuthorizationCodeWithDpopAndAttestationRetry(
		ctx,
		*flow.authorizationServerMetadata.TokenEndpoint,
		tokenRequest,
		func() (receiverTypes.OAuthClientAttestationHeaders, error) {
			tokenAttestationHeaders := attestationHeaders
			if attestationHeaders.ClientAttestation != "" {
				tokenPop, err := flow.signer.CreateClientAttestationPop(req.ClientKey, req.ClientID, flow.authorizationServerIssuer, attestationChallenge, 5*time.Minute)
				if err != nil {
					return receiverTypes.OAuthClientAttestationHeaders{}, err
				}
				tokenAttestationHeaders.ClientAttestationPop = tokenPop
			}
			return tokenAttestationHeaders, nil
		},
		func(nonce string) (string, error) {
			return flow.signer.CreateDpopProof(req.ClientKey, http.MethodPost, flow.authorizationServerMetadata.TokenEndpoint.String(), nonce, "")
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	return w.newOID4VCIFinalTokenGrant(ctx, flow, token, req.ClientKey)
}

// requestOID4VCIFinalCredentials performs the §8 credential request (with §14.6
// batch proofs, §8.2 response encryption and §6.2 credential_identifier), the
// §9 deferred flow and the §11 notification bookkeeping. Everything the request
// needs from the token exchange arrives in grant, so the two stages may be
// separated by a process restart.
func (w *Wallet) requestOID4VCIFinalCredentials(
	ctx context.Context,
	flow *oid4vciFinalFlow,
	grant *OID4VCIFinalTokenGrant,
	clientKey jose.JSONWebKey,
	encryptionKey *jose.JSONWebKey,
	deferredPollAttempts int,
	maxInterval time.Duration,
) (*OID4VCIFinalReceiveResult, error) {
	token := grant.AccessToken
	issuerMetadata := flow.issuerMetadata
	// The Holder's own policy decides first whether this issuance may be
	// encrypted at all, and generates the ephemeral §8.2 key when the caller
	// supplied none.
	encryptionKey, err := flow.policy.encryption.resolveCredentialResponseEncryptionKey(issuerMetadata, encryptionKey)
	if err != nil {
		return nil, err
	}
	// §8.2 / §10: build the credential_response_encryption request parameter and
	// fail closed when the issuer requires encryption but no key is supplied.
	encryptionParams, err := receiverOid4vci.CredentialResponseEncryptionParameters(issuerMetadata, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("credential response encryption: %w", err)
	}

	// Appendix D: an attestation the wallet can neither mint nor was given
	// stops the issuance here, before the Credential Request, and hands the
	// caller the c_nonce and holder keys to attest.
	if flow.keyAttestation != nil && flow.keyAttestation.provider == nil && flow.suppliedKeyAttestation == nil {
		return nil, newKeyAttestationRequiredError(grant, flow.keyAttestation.required)
	}
	// A caller-minted attestation is bound to one c_nonce, and Appendix F makes
	// echoing it mandatory once the issuer provided one. Checking the match
	// here, rather than leaving it to ValidateKeyAttestation on the wire, keeps
	// a stale attestation from spending the issuer's nonce.
	if flow.suppliedKeyAttestation != nil {
		_, claims, err := parseAttestationJWT(flow.suppliedKeyAttestation.JWT)
		if err != nil {
			return nil, fmt.Errorf("key attestation is malformed: %w", err)
		}
		if grant.CNonce != "" && claims.Nonce != grant.CNonce {
			return nil, newKeyAttestationNonceError(grant)
		}
		flow.suppliedKeyAttestationNonce = grant.CNonce
	}
	build := oid4vciFinalCredentialRequestBodyFactory(ctx, flow, grant.CredentialIdentifier, encryptionParams)

	if err := requireOID4VCIContext(ctx, "the credential request"); err != nil {
		return nil, err
	}
	credentialEndpoint := issuerMetadata.CredentialEndpoint
	rawResponse, cNonce, err := flow.receiver.PostCredentialEndpointWithNonceRetryForToken(
		observe.WithEndpoint(ctx, observe.EndpointCredential),
		credentialEndpoint,
		*token,
		issuerMetadata.NonceEndpoint,
		grant.CNonce,
		build,
		oid4vciFinalDpopProofFactory(flow.signer, clientKey, credentialEndpoint, token.Token),
	)
	if err != nil {
		// §8.3.1.2 "invalid_nonce" invalidated a caller-minted attestation: the
		// fresh c_nonce travels back in the grant so the caller can re-sign.
		if errors.Is(err, ErrKeyAttestationNonceStale) {
			return nil, newKeyAttestationNonceError(grant.refreshed(cNonce, flow))
		}
		// CredentialEndpointError is retained so callers can branch with
		// errors.Is (invalid_proof, credential_request_denied, ...).
		return nil, fmt.Errorf("failed to receive credential: %w", err)
	}
	if encryptionParams != nil && !strings.Contains(strings.ToLower(rawResponse.ContentType), "application/jwt") {
		return nil, fmt.Errorf("credential response encryption was requested but the credential endpoint returned %q", rawResponse.ContentType)
	}
	credentialResponse, err := decodeOID4VCIFinalCredentialResponse(flow.receiver, rawResponse, encryptionKey, flow.policy.requireSingleCredential)
	if err != nil {
		return nil, err
	}

	if credentialResponse.TransactionID != "" {
		return w.handleOID4VCIFinalDeferredResponse(ctx, flow, token, clientKey, encryptionKey, encryptionParams, credentialResponse, deferredPollAttempts, maxInterval)
	}
	return w.storeAndNotifyOID4VCIFinalCredentials(ctx, flow, token, clientKey, credentialResponse)
}

// ResumeOID4VCIFinalDeferredCredential resumes polling the §9 deferred
// credential endpoint using a transaction_id returned by an IssuancePending
// result. It is ResumeOID4VCIFinalDeferredCredentialContext with a background
// context, so its polling cannot be cancelled.
func (w *Wallet) ResumeOID4VCIFinalDeferredCredential(req OID4VCIFinalDeferredRequest) (*OID4VCIFinalReceiveResult, error) {
	return w.ResumeOID4VCIFinalDeferredCredentialContext(context.Background(), req)
}

// ResumeOID4VCIFinalDeferredCredentialContext resumes polling the §9 deferred
// credential endpoint using a transaction_id returned by an IssuancePending
// result. The issuer metadata may be supplied directly or refetched from
// IssuerURL. Cancelling ctx stops the polling between attempts.
func (w *Wallet) ResumeOID4VCIFinalDeferredCredentialContext(ctx context.Context, req OID4VCIFinalDeferredRequest) (*OID4VCIFinalReceiveResult, error) {
	if req.Type != receiverTypes.Oid4vci {
		return nil, fmt.Errorf("unsupported OID4VCI Final receiving type: %v", req.Type)
	}
	if req.AccessToken == nil {
		return nil, fmt.Errorf("access token is required")
	}
	if strings.TrimSpace(req.TransactionID) == "" {
		return nil, fmt.Errorf("transaction ID is required")
	}
	finalReceiver, err := w.receiver.OID4VCIFinalTransport(req.Type)
	if err != nil {
		return nil, fmt.Errorf("OID4VCI Final receiver capability is not available: %w", err)
	}

	issuerMetadata := req.IssuerMetadata
	if issuerMetadata == nil {
		if req.IssuerURL == nil {
			return nil, fmt.Errorf("issuer metadata or issuer URL is required")
		}
		issuerEndpoint, err := common.ParseURIField(req.IssuerURL.String())
		if err != nil {
			return nil, fmt.Errorf("failed to parse credential issuer endpoint: %w", err)
		}
		issuerMetadata, err = finalReceiver.FetchIssuerMetadata(*issuerEndpoint, req.Type)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
		}
		if issuerMetadata.CredentialIssuer != req.IssuerURL.String() {
			return nil, fmt.Errorf(
				"credential issuer metadata identifier %q does not match the credential offer credential_issuer %q",
				issuerMetadata.CredentialIssuer, req.IssuerURL.String())
		}
	}
	if issuerMetadata.DeferredCredentialEndpoint == nil {
		return nil, fmt.Errorf("deferred credential endpoint is missing on credential issuer")
	}

	holderKeys, err := resolveOID4VCIFinalHolderKeys(OID4VCIFinalReceiveRequest{
		HolderKey:            req.HolderKey,
		AdditionalHolderKeys: req.AdditionalHolderKeys,
	}, true)
	if err != nil {
		return nil, err
	}
	if len(holderKeys) > issuerMetadata.BatchSize() {
		return nil, fmt.Errorf("requested %d credentials but the issuer batch_size is %d", len(holderKeys), issuerMetadata.BatchSize())
	}

	encryptionKey, err := req.CredentialEncryption.resolveCredentialResponseEncryptionKey(issuerMetadata, req.CredentialResponseEncryptionKey)
	if err != nil {
		return nil, err
	}
	encryptionParams, err := receiverOid4vci.CredentialResponseEncryptionParameters(issuerMetadata, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("credential response encryption: %w", err)
	}

	attempts := req.DeferredPollAttempts
	if attempts <= 0 {
		attempts = 1
	}
	interval := clampDeferredInterval(req.Interval, req.MaxInterval)
	if interval <= 0 {
		interval = defaultDeferredInterval
	}
	flow := &oid4vciFinalFlow{
		receiver:                  finalReceiver,
		signer:                    w.oid4vciFinalSigner(finalReceiver),
		issuerMetadata:            issuerMetadata,
		credentialConfigurationID: req.CredentialConfigurationID,
		credentialConfiguration:   issuerMetadata.CredentialConfigurationSupported[req.CredentialConfigurationID],
		holderKeys:                holderKeys,
		policy: oid4vciFinalCredentialPolicy{
			encryption:              req.CredentialEncryption,
			skipNotification:        req.SkipNotification,
			requireSingleCredential: req.RequireSingleCredential,
		},
	}
	return w.pollOID4VCIFinalDeferredCredential(ctx, flow, req.AccessToken, req.ClientKey, encryptionKey, encryptionParams, req.TransactionID, "", attempts, interval, req.MaxInterval)
}
