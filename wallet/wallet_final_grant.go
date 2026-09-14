package wallet

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// preAuthorizedCodeGrantType is the OpenID4VCI 1.0 §4.1.1 grant type of the
// Pre-Authorized Code Flow, registered in §16.4.
const preAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// dpopTokenType is the RFC 9449 §7.1 token_type of a DPoP-bound access token.
// RFC 6749 §7.1 defines token_type as case insensitive, so it is only ever
// compared with strings.EqualFold.
const dpopTokenType = "DPoP"

// OID4VCIFinalTokenGrant is everything the OpenID4VCI 1.0 §8 Credential Request
// needs from the §6.1 Token Response, in a form that survives being written to
// a database and read back in another process.
//
// It is the second interruption point of a Final issuance. The first one is the
// browser: BeginOID4VCIFinalAuthorization hands out an OID4VCIFinalAuthorization
// and AuthorizeOID4VCIFinalToken consumes it. The second one is the key
// attestation: OpenID4VCI 1.0 Appendix D binds the attestation to the issuer's
// c_nonce, so a wallet whose attester lives outside this process cannot sign it
// before the token exchange has happened. AuthorizeOID4VCIFinalToken stops
// there and returns this grant; RequestOID4VCIFinalCredential resumes from it.
//
// The grant carries an access token. A caller that persists it must treat it as
// a credential: encrypt it at rest and keep it out of logs and traces.
type OID4VCIFinalTokenGrant struct {
	// AccessToken is the parsed §6.2 Token Response, including its token_type,
	// so the Credential Request presents the token with the scheme the
	// authorization server issued (RFC 6750 §2.1 Bearer or RFC 9449 §7.1 DPoP).
	AccessToken *receiverTypes.CredentialIssuanceAccessToken `json:"access_token"`
	// CNonce is the §7.2 c_nonce the Credential Request proof — and any key
	// attestation inside it — must carry. Empty when the Credential Issuer
	// advertises no nonce_endpoint, which §7 permits.
	CNonce string `json:"c_nonce,omitempty"`
	// DPoPNonces is the RFC 9449 §8.2 per-server nonce store exported from the
	// receiver, so the first DPoP proof built after the interruption already
	// carries the nonce each server last issued instead of paying a challenge
	// round trip.
	DPoPNonces map[string]string `json:"dpop_nonces,omitempty"`
	// DPoPKeyThumbprint is the RFC 7638 thumbprint of the key the access token
	// is bound to, set only for a DPoP-bound token. RequestOID4VCIFinalCredential
	// refuses a different key rather than sending a proof the issuer will
	// reject (ErrDPoPKeyMismatch).
	DPoPKeyThumbprint string `json:"dpop_key_thumbprint,omitempty"`
	// CredentialIdentifier is the §6.2 credential_identifier the Credential
	// Request must name; nil when the request names the Credential
	// Configuration instead (§8.1).
	CredentialIdentifier *string `json:"credential_identifier,omitempty"`
	// CredentialConfigurationID is the Credential Configuration this grant was
	// obtained for.
	CredentialConfigurationID string `json:"credential_configuration_id"`
	// IssuerMetadata is the §12.2.2 Credential Issuer metadata the flow was
	// built from. The credential stage uses this snapshot rather than a fresh
	// fetch, so the request goes to exactly the issuer the token was obtained
	// from.
	IssuerMetadata *receiverTypes.CredentialIssuerMetadata `json:"issuer_metadata"`
	// AuthorizationServerMetadata and AuthorizationServerIssuer record which
	// authorization server issued the token. They are not needed to spend the
	// grant; they are carried so a caller can report and audit the issuance
	// from the persisted state alone.
	AuthorizationServerMetadata *receiverTypes.AuthorizationServerMetadata `json:"authorization_server_metadata,omitempty"`
	AuthorizationServerIssuer   string                                     `json:"authorization_server_issuer,omitempty"`
	// KeyAttestation is the Appendix D request the caller must satisfy before
	// the Credential Request can be sent, present only when this issuance needs
	// an attestation. Its Keys are public.
	KeyAttestation *KeyAttestationRequest `json:"key_attestation,omitempty"`
}

// refreshed returns a copy of the grant that names a new c_nonce, with the key
// attestation request and the exported DPoP nonces brought up to date. It is
// what travels back to the caller when §8.3.1.2 "invalid_nonce" invalidated an
// attestation that was signed out of process.
func (g *OID4VCIFinalTokenGrant) refreshed(cNonce string, flow *oid4vciFinalFlow) *OID4VCIFinalTokenGrant {
	refreshed := *g
	refreshed.CNonce = cNonce
	if g.KeyAttestation != nil {
		attestation := *g.KeyAttestation
		attestation.Nonce = cNonce
		refreshed.KeyAttestation = &attestation
	}
	if nonces := exportOID4VCIDPoPNonces(flow); len(nonces) > 0 {
		refreshed.DPoPNonces = nonces
	}
	return &refreshed
}

// KeyAttestationRequiredError reports that the Credential Request cannot be
// built because it needs an OpenID4VCI 1.0 Appendix D key attestation that this
// process cannot mint: the request set ExternalKeyAttestation and supplied no
// KeyAttestation, and no Config.KeyAttestation provider is configured.
//
// Nothing has been sent to the Credential Endpoint. The caller signs a
// key-attestation+jwt over HolderKeys with CNonce as its nonce and Audience as
// its aud, then calls RequestOID4VCIFinalCredential again with the same Grant
// and OID4VCIFinalReceiveRequest.KeyAttestation set.
type KeyAttestationRequiredError struct {
	// Grant is the token grant to present again, unchanged.
	Grant *OID4VCIFinalTokenGrant
	// CNonce is the §7.2 c_nonce the attestation's nonce claim must carry;
	// empty when the issuer advertises no nonce_endpoint.
	CNonce string
	// HolderKeys are the public holder keys to list in attested_keys, in proof
	// order. There is more than one only for a §14.6 batch request.
	HolderKeys []jose.JSONWebKey
	// Audience is the Credential Issuer Identifier the attestation is for.
	Audience string
	// IssuerRequired distinguishes an attestation the Credential Issuer demands
	// through proof_types_supported.jwt.key_attestations_required (Appendix D)
	// from one the wallet volunteered with IncludeKeyAttestation. Only the
	// latter can be abandoned by retrying without an attestation.
	IssuerRequired bool
}

func newKeyAttestationRequiredError(grant *OID4VCIFinalTokenGrant, issuerRequired bool) *KeyAttestationRequiredError {
	err := &KeyAttestationRequiredError{Grant: grant, CNonce: grant.CNonce, IssuerRequired: issuerRequired}
	if grant.KeyAttestation != nil {
		err.HolderKeys = grant.KeyAttestation.Keys
		err.Audience = grant.KeyAttestation.Audience
	}
	return err
}

func (e *KeyAttestationRequiredError) Error() string {
	if e == nil {
		return ErrKeyAttestationRequired.Error()
	}
	return fmt.Sprintf("%s: sign a key-attestation+jwt for %d holder key(s) with nonce %q and aud %q",
		ErrKeyAttestationRequired, len(e.HolderKeys), e.CNonce, e.Audience)
}

// Unwrap makes errors.Is(err, ErrKeyAttestationRequired) hold.
func (e *KeyAttestationRequiredError) Unwrap() error { return ErrKeyAttestationRequired }

// KeyAttestationNonceError reports that a caller-supplied key attestation is
// not usable for the c_nonce the Credential Request must carry: either it was
// minted for another nonce, or the Credential Issuer answered §8.3.1.2
// "invalid_nonce" and handed out a fresh one. Appendix D attestations are
// single use, so the caller signs a new one for Grant.CNonce and calls
// RequestOID4VCIFinalCredential again with the Grant carried here.
type KeyAttestationNonceError struct {
	// Grant is the token grant to resume from. Its CNonce and KeyAttestation
	// name the nonce the new attestation must carry.
	Grant *OID4VCIFinalTokenGrant
}

func newKeyAttestationNonceError(grant *OID4VCIFinalTokenGrant) *KeyAttestationNonceError {
	return &KeyAttestationNonceError{Grant: grant}
}

func (e *KeyAttestationNonceError) Error() string {
	if e == nil || e.Grant == nil {
		return ErrKeyAttestationNonceStale.Error()
	}
	return fmt.Sprintf("%s: sign a new key attestation for c_nonce %q", ErrKeyAttestationNonceStale, e.Grant.CNonce)
}

// Unwrap makes errors.Is(err, ErrKeyAttestationNonceStale) hold.
func (e *KeyAttestationNonceError) Unwrap() error { return ErrKeyAttestationNonceStale }

// dpopNonceExporter and dpopNonceImporter are the RFC 9449 §8.2 nonce store of
// a receiver transport. They are optional: a transport that keeps no nonces
// simply pays the challenge round trip after an interruption.
type dpopNonceExporter interface {
	ExportDPoPNonces() map[string]string
}

type dpopNonceImporter interface {
	ImportDPoPNonces(nonces map[string]string)
}

func exportOID4VCIDPoPNonces(flow *oid4vciFinalFlow) map[string]string {
	exporter, ok := flow.receiver.(dpopNonceExporter)
	if !ok {
		return nil
	}
	nonces := exporter.ExportDPoPNonces()
	if len(nonces) == 0 {
		return nil
	}
	return nonces
}

func importOID4VCIDPoPNonces(flow *oid4vciFinalFlow, nonces map[string]string) {
	if len(nonces) == 0 {
		return
	}
	if importer, ok := flow.receiver.(dpopNonceImporter); ok {
		importer.ImportDPoPNonces(nonces)
	}
}

// isDPoPAccessToken reports whether a Token Response bound its access token to
// the wallet's key with the RFC 9449 §7.1 DPoP scheme.
func isDPoPAccessToken(token *receiverTypes.CredentialIssuanceAccessToken) bool {
	return token != nil && strings.EqualFold(strings.TrimSpace(token.TokenType), dpopTokenType)
}

// newOID4VCIFinalTokenGrant collects the Token Response, the §6.2
// credential_identifier and the §7 c_nonce into the state the credential stage
// resumes from. The c_nonce is fetched here, before the interruption, because
// Appendix D binds a key attestation to it: a caller that signs the attestation
// elsewhere has to know the nonce while the flow is still stopped.
func (w *Wallet) newOID4VCIFinalTokenGrant(
	ctx context.Context,
	flow *oid4vciFinalFlow,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
) (*OID4VCIFinalTokenGrant, error) {
	issuerMetadata := flow.issuerMetadata
	credentialIdentifier, err := CredentialIdentifierForConfiguration(token, flow.credentialConfigurationID, flow.authorizationDetailsMode)
	if err != nil {
		return nil, err
	}

	// §7: the nonce endpoint is OPTIONAL, and Appendix F only requires the
	// attestation to echo a c_nonce "if the Credential Issuer provided" one. A
	// HAIP issuer has no such latitude: "If the Issuer supports Credential
	// Configurations that require key binding ... the nonce_endpoint MUST be
	// present in the Credential Issuer Metadata".
	nonceEndpoint := issuerMetadata.NonceEndpoint
	if nonceEndpoint == nil && flow.keyAttestation != nil && w.profile.IsHAIP() {
		return nil, fmt.Errorf(
			"the credential configuration %q requires a key attestation: %w",
			flow.credentialConfigurationID, ErrNonceEndpointRequired)
	}
	cNonce := ""
	if nonceEndpoint != nil {
		nonceResponse, err := flow.receiver.FetchNonceResponse(ctx, *nonceEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch credential nonce: %w", err)
		}
		cNonce = nonceResponse.CNonce
	}

	grant := &OID4VCIFinalTokenGrant{
		AccessToken:                 token,
		CNonce:                      cNonce,
		CredentialIdentifier:        credentialIdentifier,
		CredentialConfigurationID:   flow.credentialConfigurationID,
		IssuerMetadata:              issuerMetadata,
		AuthorizationServerMetadata: flow.authorizationServerMetadata,
		AuthorizationServerIssuer:   flow.authorizationServerIssuer,
		DPoPNonces:                  exportOID4VCIDPoPNonces(flow),
	}
	if flow.keyAttestation != nil {
		// Only public keys leave the wallet: the attester needs the key
		// material to list in attested_keys, never the private half.
		attestedKeys := make([]jose.JSONWebKey, 0, len(flow.holderKeys))
		for _, key := range flow.holderKeys {
			attestedKeys = append(attestedKeys, publicHolderJWK(key))
		}
		grant.KeyAttestation = &KeyAttestationRequest{
			Keys:     attestedKeys,
			Nonce:    cNonce,
			Audience: issuerMetadata.CredentialIssuer,
		}
	}
	if isDPoPAccessToken(token) {
		thumbprint, err := jwkThumbprint(clientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to compute the DPoP key thumbprint: %w", err)
		}
		grant.DPoPKeyThumbprint = thumbprint
	}
	return grant, nil
}

// AuthorizeOID4VCIFinalToken is the first half of a resumed OpenID4VCI 1.0 §5
// authorization code issuance: it validates the redirect the browser delivered
// against auth (RFC 6749 §4.1.2 and the RFC 9207 iss parameter), exchanges the
// code at the §6.1 Token Endpoint, resolves the §6.2 credential_identifier and
// fetches the §7 c_nonce. Everything the Credential Request needs comes back in
// a JSON-serialisable OID4VCIFinalTokenGrant, so the flow may stop here while a
// key attestation is minted elsewhere.
//
// req must carry the same client, redirect_uri and holder keys the matching
// BeginOID4VCIFinalAuthorization call used.
// ResumeOID4VCIFinalAuthorization is this call followed by
// RequestOID4VCIFinalCredential and behaves identically.
func (w *Wallet) AuthorizeOID4VCIFinalToken(ctx context.Context, req OID4VCIFinalReceiveRequest, auth *OID4VCIFinalAuthorization, redirectURL string) (*OID4VCIFinalTokenGrant, error) {
	if auth == nil {
		return nil, fmt.Errorf("authorization state is required")
	}
	flow, err := w.restoreOID4VCIFinalFlow(req, auth)
	if err != nil {
		return nil, err
	}
	return w.authorizeOID4VCIFinalToken(ctx, req, auth, flow, redirectURL)
}

// RequestOID4VCIFinalCredential is the second half: it performs the §8
// Credential Request with the §8.2.1.1 key proofs (and the Appendix D key
// attestation, from req.KeyAttestation or from a configured provider), decodes
// and accepts the response, stores the credentials and handles the §9 deferred
// transaction and the §11 notification.
//
// grant may have been marshalled to JSON and read back in another process; the
// wallet it is presented to needs the same holder keys, credential store and
// acceptance policy, but no memory of the token exchange. Two conditions stop
// the call and hand the caller an updated grant instead of an error it can only
// report: *KeyAttestationRequiredError when no attestation is available, and
// *KeyAttestationNonceError when the one supplied does not match the c_nonce
// the request must carry.
func (w *Wallet) RequestOID4VCIFinalCredential(ctx context.Context, req OID4VCIFinalReceiveRequest, grant *OID4VCIFinalTokenGrant) (*OID4VCIFinalReceiveResult, error) {
	flow, err := w.restoreOID4VCIFinalCredentialFlow(req.Type, grant, oid4vciFinalCredentialInputs{
		holderKey:              req.HolderKey,
		additionalHolderKeys:   req.AdditionalHolderKeys,
		includeKeyAttestation:  req.IncludeKeyAttestation,
		externalKeyAttestation: req.ExternalKeyAttestation,
		keyAttestation:         req.KeyAttestation,
	})
	if err != nil {
		return nil, err
	}
	if err := requireOID4VCIFinalGrantKey(grant, req.ClientKey); err != nil {
		return nil, err
	}
	importOID4VCIDPoPNonces(flow, grant.DPoPNonces)
	return w.requestOID4VCIFinalCredentials(ctx, flow, grant, req.ClientKey, req.CredentialResponseEncryptionKey, req.DeferredPollAttempts, req.MaxDeferredInterval)
}

// requireOID4VCIFinalGrantKey refuses to present a DPoP-bound access token with
// a key other than the one it was issued to. RFC 9449 §5 binds the token to the
// public key in the proof, so another key cannot succeed, and catching it here
// names the cause instead of surfacing an opaque 401.
func requireOID4VCIFinalGrantKey(grant *OID4VCIFinalTokenGrant, clientKey jose.JSONWebKey) error {
	if grant.DPoPKeyThumbprint == "" {
		return nil
	}
	if clientKey.Key == nil {
		return fmt.Errorf("the access token is DPoP-bound but no client key was supplied: %w", ErrDPoPKeyMismatch)
	}
	thumbprint, err := jwkThumbprint(clientKey)
	if err != nil {
		return fmt.Errorf("failed to compute the DPoP key thumbprint: %w", err)
	}
	if thumbprint != grant.DPoPKeyThumbprint {
		return ErrDPoPKeyMismatch
	}
	return nil
}

// oid4vciFinalCredentialInputs are the per-request inputs the §8 Credential
// Request stage needs. They are shared by the authorization code and
// Pre-Authorized Code entry points, which carry different request types but
// exactly the same credential stage.
type oid4vciFinalCredentialInputs struct {
	holderKey              jose.JSONWebKey
	additionalHolderKeys   []jose.JSONWebKey
	includeKeyAttestation  bool
	externalKeyAttestation bool
	keyAttestation         *KeyAttestation
}

// restoreOID4VCIFinalCredentialFlow rebuilds the non-serialisable half of an
// issuance from a token grant. The issuer metadata comes from the grant, not
// from a fresh fetch, so the credential request goes to exactly the issuer the
// access token was obtained from; the wallet profile, the batch size and the
// key attestation plan are re-evaluated here, so a grant decoded into another
// wallet is judged by that wallet's policy.
func (w *Wallet) restoreOID4VCIFinalCredentialFlow(receivingType receiverTypes.SupportedReceivingTypes, grant *OID4VCIFinalTokenGrant, in oid4vciFinalCredentialInputs) (*oid4vciFinalFlow, error) {
	if receivingType != receiverTypes.Oid4vci {
		return nil, fmt.Errorf("unsupported OID4VCI Final receiving type: %v", receivingType)
	}
	if grant == nil {
		return nil, fmt.Errorf("token grant is required")
	}
	if grant.AccessToken == nil || strings.TrimSpace(grant.AccessToken.Token) == "" {
		return nil, fmt.Errorf("token grant is missing the access token")
	}
	if grant.IssuerMetadata == nil {
		return nil, fmt.Errorf("token grant is missing the issuer metadata")
	}
	finalReceiver, err := w.receiver.OID4VCIFinalTransport(receivingType)
	if err != nil {
		return nil, fmt.Errorf("OID4VCI Final receiver capability is not available: %w", err)
	}
	return w.newOID4VCIFinalCredentialFlow(finalReceiver, grant.IssuerMetadata, grant.CredentialConfigurationID, in)
}

// newOID4VCIFinalCredentialFlow builds the flow the §8 Credential Request runs
// on. It is newOID4VCIFinalFlow without the authorization-request half: no
// client authentication is resolved, because the token has already been
// obtained, and no §5.1.1/§5.1.2 decision is repeated, because the §6.2
// credential_identifier the grant carries already records its outcome.
func (w *Wallet) newOID4VCIFinalCredentialFlow(
	finalReceiver receiverTypes.OID4VCIFinalTransport,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	credentialConfigurationID string,
	in oid4vciFinalCredentialInputs,
) (*oid4vciFinalFlow, error) {
	holderKeys, err := resolveOID4VCIFinalHolderKeys(OID4VCIFinalReceiveRequest{
		HolderKey:            in.holderKey,
		AdditionalHolderKeys: in.additionalHolderKeys,
	})
	if err != nil {
		return nil, err
	}
	config, err := requireOfferedCredentialConfiguration(issuerMetadata, credentialConfigurationID)
	if err != nil {
		return nil, err
	}

	profileValidator, _ := finalReceiver.(oid4vciProfileValidator)
	if w.profile.IsHAIP() && profileValidator == nil {
		return nil, fmt.Errorf("HAIP requires a receiver plugin that validates issuer metadata against the profile")
	}
	if profileValidator != nil {
		if err := profileValidator.ValidateIssuerMetadataForProfile(issuerMetadata); err != nil {
			return nil, fmt.Errorf("issuer metadata does not satisfy the wallet profile: %w", err)
		}
		if err := profileValidator.ValidateCredentialConfigurationForProfile(config); err != nil {
			return nil, fmt.Errorf("credential configuration does not satisfy the wallet profile: %w", err)
		}
	}

	keyAttestation, err := w.planOID4VCIKeyAttestation(
		issuerMetadata,
		credentialConfigurationID,
		in.includeKeyAttestation || in.keyAttestation != nil,
		in.externalKeyAttestation || in.keyAttestation != nil,
	)
	if err != nil {
		return nil, err
	}

	// §14.6: never request more proofs than the issuer's batch_size.
	if len(holderKeys) > issuerMetadata.BatchSize() {
		return nil, fmt.Errorf("requested %d credentials but the issuer batch_size is %d", len(holderKeys), issuerMetadata.BatchSize())
	}

	return &oid4vciFinalFlow{
		receiver:                  finalReceiver,
		signer:                    w.oid4vciFinalSigner(finalReceiver),
		issuerMetadata:            issuerMetadata,
		credentialConfigurationID: credentialConfigurationID,
		credentialConfiguration:   config,
		holderKeys:                holderKeys,
		keyAttestation:            keyAttestation,
		suppliedKeyAttestation:    in.keyAttestation,
	}, nil
}

// OID4VCIFinalPreAuthorizedReceiveRequest holds the OpenID4VCI 1.0 §4.1.1
// Pre-Authorized Code Flow inputs that are not discoverable from the Credential
// Offer or the issuer metadata.
type OID4VCIFinalPreAuthorizedReceiveRequest struct {
	// CredentialOffer must carry a
	// urn:ietf:params:oauth:grant-type:pre-authorized_code grant. The first
	// credential_configuration_ids entry is the one requested.
	CredentialOffer *CredentialOffer
	Type            receiverTypes.SupportedReceivingTypes
	// TxCode is the §6.1 tx_code value. It is REQUIRED, and only permitted,
	// when the offer's grant carries a tx_code object: "This value MUST be
	// present if a tx_code object was present in the Credential Offer
	// (including if the object was empty)."
	TxCode string
	// ClientID names the client in the token request. §6.1 makes it OPTIONAL
	// for this grant type — "authentication of the Client is OPTIONAL ... the
	// client_id parameter is only needed when a form of Client Authentication
	// that relies on this parameter is used" — so an empty value sends an
	// anonymous request. HAIP has no anonymous clients: §4.4.1 requires an
	// OAuth2 client authentication mechanism, so a client_id is required there.
	ClientID string
	// AuthorizationServer overrides the offer grant's authorization_server
	// hint. Like the hint, the value MUST be one of the issuer metadata's
	// authorization_servers.
	AuthorizationServer string
	HolderKey           jose.JSONWebKey
	// AdditionalHolderKeys requests §14.6 batch issuance, exactly as on the
	// authorization code path.
	AdditionalHolderKeys []jose.JSONWebKey
	// ClientKey is the wallet instance key. It signs the RFC 9449 DPoP proof on
	// the token request and on every request that presents a DPoP-bound access
	// token, and the Client Attestation PoP. Without it the flow is anonymous
	// and only a Bearer token can be accepted.
	ClientKey jose.JSONWebKey
	// IncludeKeyAttestation, ExternalKeyAttestation and KeyAttestation behave
	// as the identically named members of OID4VCIFinalReceiveRequest.
	IncludeKeyAttestation  bool
	ExternalKeyAttestation bool
	KeyAttestation         *KeyAttestation
	// DeferredPollAttempts is the number of §9 deferred credential endpoint
	// polls. Zero means do not poll and return an IssuancePending result.
	DeferredPollAttempts int
	// MaxDeferredInterval caps the §9.2 polling interval. Zero uses the
	// library's 60 second cap.
	MaxDeferredInterval             time.Duration
	CredentialResponseEncryptionKey *jose.JSONWebKey
}

// ReceiveOID4VCIFinalPreAuthorizedCredential runs the whole OpenID4VCI 1.0
// §4.1.1 / §6.1 Pre-Authorized Code Flow against a Final or HAIP Credential
// Issuer: the token request with pre-authorized_code and tx_code, the §7 nonce,
// the §8 Credential Request with §8.2.1.1 key proofs, §8.2 response encryption
// and the Appendix D key attestation, credential acceptance and storage, and
// the §9 deferred and §11 notification bookkeeping. No browser is involved, so
// unlike the authorization code flow it completes in one call.
//
// It is AuthorizeOID4VCIFinalPreAuthorizedToken followed by
// RequestOID4VCIFinalCredential; a wallet whose key attester lives in another
// process calls those two instead.
func (w *Wallet) ReceiveOID4VCIFinalPreAuthorizedCredential(ctx context.Context, req OID4VCIFinalPreAuthorizedReceiveRequest) (*OID4VCIFinalReceiveResult, error) {
	grant, flow, err := w.authorizeOID4VCIFinalPreAuthorizedToken(ctx, req)
	if err != nil {
		return nil, err
	}
	return w.requestOID4VCIFinalCredentials(ctx, flow, grant, req.ClientKey, req.CredentialResponseEncryptionKey, req.DeferredPollAttempts, req.MaxDeferredInterval)
}

// AuthorizeOID4VCIFinalPreAuthorizedToken performs the §6.1 Pre-Authorized Code
// token request and stops with the grant the §8 Credential Request needs, so
// the Appendix D key attestation can be minted outside this process. It is the
// Pre-Authorized Code counterpart of AuthorizeOID4VCIFinalToken.
func (w *Wallet) AuthorizeOID4VCIFinalPreAuthorizedToken(ctx context.Context, req OID4VCIFinalPreAuthorizedReceiveRequest) (*OID4VCIFinalTokenGrant, error) {
	grant, _, err := w.authorizeOID4VCIFinalPreAuthorizedToken(ctx, req)
	return grant, err
}

func (w *Wallet) authorizeOID4VCIFinalPreAuthorizedToken(ctx context.Context, req OID4VCIFinalPreAuthorizedReceiveRequest) (*OID4VCIFinalTokenGrant, *oid4vciFinalFlow, error) {
	grantParameters, credentialConfigurationID, err := validateOID4VCIFinalPreAuthorizedRequest(req)
	if err != nil {
		return nil, nil, err
	}
	if err := requireOID4VCIContext(ctx, "issuer metadata discovery"); err != nil {
		return nil, nil, err
	}
	haip := w.profile.IsHAIP()
	// HAIP §4.4.1: "Wallets MUST use ... an OAuth2 Client authentication
	// mechanism at OAuth2 Endpoints that support client authentication (such as
	// the PAR and Token Endpoints)". §6.1 lets the Pre-Authorized Code grant go
	// out anonymously; HAIP does not.
	if haip {
		if strings.TrimSpace(req.ClientID) == "" {
			return nil, nil, fmt.Errorf("HAIP requires a client_id on the pre-authorized_code token request")
		}
		if !clientAuthenticationConfigured(w.clientAuth) && w.clientAttestation == nil {
			return nil, nil, fmt.Errorf("HAIP requires an OAuth2 client authentication mechanism")
		}
		// HAIP §4: "Sender-constrained access token: MUST support DPoP".
		if req.ClientKey.Key == nil {
			return nil, nil, fmt.Errorf("HAIP requires a client key to sign the DPoP proof on the token request")
		}
	}

	finalReceiver, err := w.receiver.OID4VCIFinalTransport(req.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("OID4VCI Final receiver capability is not available: %w", err)
	}

	issuerIdentifier := req.CredentialOffer.CredentialIssuer.String()
	issuerEndpoint, err := common.ParseURIField(issuerIdentifier)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse credential issuer endpoint: %w", err)
	}
	issuerMetadata, err := finalReceiver.FetchIssuerMetadata(*issuerEndpoint, req.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
	}
	// §12.2.2/§12.2.4: the credential_issuer value in the metadata MUST match
	// the credential issuer the offer named, with no normalization.
	if issuerMetadata.CredentialIssuer != issuerIdentifier {
		return nil, nil, fmt.Errorf(
			"credential issuer metadata identifier %q does not match the credential offer credential_issuer %q",
			issuerMetadata.CredentialIssuer, issuerIdentifier)
	}

	// §12.3: an authorization_server hint MUST be listed in the issuer
	// metadata's authorization_servers.
	serverHint := grantParameters
	if server := strings.TrimSpace(req.AuthorizationServer); server != "" {
		hinted := *grantParameters
		hinted.AuthorizationServer = server
		serverHint = &hinted
	}
	authorizationServerEndpoint, err := SelectOID4VCIAuthorizationServer(issuerMetadata, serverHint, *issuerEndpoint)
	if err != nil {
		return nil, nil, err
	}
	authorizationServerMetadata, err := finalReceiver.FetchAuthorizationServerMetadata(authorizationServerEndpoint, req.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}
	if authorizationServerMetadata.TokenEndpoint == nil {
		return nil, nil, fmt.Errorf("token endpoint is missing on authorization server")
	}
	// RFC 8414 §3.3: the issuer identifier in the metadata MUST be identical to
	// the authorization server identifier used to fetch it.
	if authorizationServerMetadata.Issuer.String() != authorizationServerEndpoint.String() {
		return nil, nil, fmt.Errorf(
			"authorization server metadata issuer %q does not match the selected authorization server %q",
			authorizationServerMetadata.Issuer.String(), authorizationServerEndpoint.String())
	}

	flow, err := w.newOID4VCIFinalCredentialFlow(finalReceiver, issuerMetadata, credentialConfigurationID, oid4vciFinalCredentialInputs{
		holderKey:              req.HolderKey,
		additionalHolderKeys:   req.AdditionalHolderKeys,
		includeKeyAttestation:  req.IncludeKeyAttestation,
		externalKeyAttestation: req.ExternalKeyAttestation,
		keyAttestation:         req.KeyAttestation,
	})
	if err != nil {
		return nil, nil, err
	}
	flow.authorizationServerMetadata = authorizationServerMetadata
	flow.authorizationServerIssuer = authorizationServerMetadata.Issuer.String()
	// §6.2 makes authorization_details in the Token Response "OPTIONAL when
	// scope parameter was used"; the Pre-Authorized Code request sends neither,
	// so an absent member is normal and the Credential Request names the
	// Credential Configuration instead (§8.1).
	flow.authorizationDetailsMode = AuthorizationDetailsOptional

	if err := requireOID4VCIContext(ctx, "the token request"); err != nil {
		return nil, nil, err
	}
	token, err := w.fetchOID4VCIFinalPreAuthorizedToken(flow, req, grantParameters.PreAuthorizedCode, haip)
	if err != nil {
		return nil, nil, err
	}
	grant, err := w.newOID4VCIFinalTokenGrant(ctx, flow, token, req.ClientKey)
	if err != nil {
		return nil, nil, err
	}
	return grant, flow, nil
}

// validateOID4VCIFinalPreAuthorizedRequest checks the request and the offer
// before anything is sent, and returns the §4.1.1 grant parameters and the
// Credential Configuration the flow requests.
func validateOID4VCIFinalPreAuthorizedRequest(req OID4VCIFinalPreAuthorizedReceiveRequest) (*CredentialOfferGrant, string, error) {
	if req.Type != receiverTypes.Oid4vci {
		return nil, "", fmt.Errorf("unsupported OID4VCI Final receiving type: %v", req.Type)
	}
	if req.HolderKey.Key == nil {
		return nil, "", fmt.Errorf("holder key is required")
	}
	if req.CredentialOffer == nil {
		return nil, "", fmt.Errorf("credential offer is required")
	}
	if req.CredentialOffer.CredentialIssuer == nil {
		return nil, "", fmt.Errorf("credential issuer is required")
	}
	if len(req.CredentialOffer.CredentialConfigurationIDs) == 0 {
		return nil, "", fmt.Errorf("credential configuration IDs are empty")
	}
	grantParameters := req.CredentialOffer.Grants[preAuthorizedCodeGrantType]
	if grantParameters == nil || strings.TrimSpace(grantParameters.PreAuthorizedCode) == "" {
		return nil, "", ErrPreAuthorizedGrantMissing
	}
	// §6.1: "tx_code ... MUST be present if a tx_code object was present in the
	// Credential Offer (including if the object was empty)", and "This
	// parameter MUST only be used if the grant_type is
	// urn:ietf:params:oauth:grant-type:pre-authorized_code". Both halves are
	// checked before the single-use pre-authorized_code is spent.
	switch {
	case grantParameters.TxCode != nil && strings.TrimSpace(req.TxCode) == "":
		return nil, "", ErrTransactionCodeRequired
	case grantParameters.TxCode == nil && req.TxCode != "":
		return nil, "", fmt.Errorf("the credential offer declares no tx_code, so none may be sent")
	}
	return grantParameters, req.CredentialOffer.CredentialConfigurationIDs[0], nil
}

// fetchOID4VCIFinalPreAuthorizedToken performs the §6.1 token request. It owns
// the one RFC 9449 §8 "use_dpop_nonce" retry, re-signing the proof with the
// nonce the authorization server named, and decides what token_type the
// response may carry.
func (w *Wallet) fetchOID4VCIFinalPreAuthorizedToken(
	flow *oid4vciFinalFlow,
	req OID4VCIFinalPreAuthorizedReceiveRequest,
	preAuthorizedCode string,
	haip bool,
) (*receiverTypes.CredentialIssuanceAccessToken, error) {
	tokenEndpoint := *flow.authorizationServerMetadata.TokenEndpoint
	tokenEndpointURL := receiverTypes.ResolveTokenEndpointURL(tokenEndpoint)

	// Attestation-based client authentication (Appendix E) travels in the
	// OAuth-Client-Attestation headers, which the Receiver token request cannot
	// carry. Sending the request anonymously instead would silently drop the
	// authentication HAIP §4.4.1 requires, so it fails closed there; under
	// Final the grant needs no client authentication at all (§6.1) and the
	// request goes out without it.
	if haip && w.clientAttestation != nil && !clientAuthenticationConfigured(w.clientAuth) {
		return nil, ErrClientAttestationNotCarried
	}

	authMethod, ok := resolveClientAuthMethod(w.clientAuth, flow.authorizationServerMetadata)
	if !ok {
		return nil, errNoUsableClientAuthMethod
	}
	clientAssertionAudience := resolveClientAssertionAudience(w.clientAuth, flow.authorizationServerMetadata, tokenEndpointURL)
	// RFC 9449 §5 binds the access token to the proof key. A proof is sent
	// whenever the wallet holds a key for it: a server that does not implement
	// DPoP ignores the header and issues a Bearer token, and HAIP §4 requires
	// the sender-constrained token the proof makes possible.
	useDPoP := req.ClientKey.Key != nil

	fetch := func(dpopNonce string) (*receiverTypes.CredentialIssuanceAccessToken, error) {
		var options []receiverTypes.TokenRequestOption
		switch authMethod {
		case receiverTypes.PrivateKeyJwt:
			// RFC 7523 §3 requires a unique jti, so every attempt signs a new
			// assertion instead of replaying the first one.
			assertion, err := w.generateClientAssertion(
				w.clientAuth.Key,
				w.clientAuth.ClientID,
				clientAssertionAudience,
				w.clientAuth.signatureAlgorithm(),
			)
			if err != nil {
				return nil, fmt.Errorf("failed to generate client assertion: %w", err)
			}
			options = append(options, receiverTypes.WithClientAssertion(w.clientAuth.ClientID, assertion))
		default:
			if clientID := strings.TrimSpace(req.ClientID); clientID != "" {
				options = append(options, receiverTypes.WithClientID(clientID))
			}
		}
		if useDPoP {
			proof, err := flow.signer.CreateDpopProof(req.ClientKey, http.MethodPost, tokenEndpointURL, dpopNonce, "")
			if err != nil {
				return nil, fmt.Errorf("failed to create the token request DPoP proof: %w", err)
			}
			options = append(options, receiverTypes.WithDPoPProof(proof))
		}
		return flow.receiver.FetchAccessToken(req.Type, tokenEndpoint, preAuthorizedCode, req.TxCode, options...)
	}

	token, err := fetch(oid4vciDPoPNonceFor(flow, tokenEndpointURL, useDPoP))
	if err != nil && useDPoP {
		if nonce, retry := receiverTypes.DPoPNonceFromError(err); retry && nonce != "" {
			token, err = fetch(nonce)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to exchange the pre-authorized code: %w", err)
	}
	if strings.TrimSpace(token.Token) == "" {
		return nil, fmt.Errorf("token response did not contain an access token")
	}
	if !useDPoP {
		// An anonymous wallet holds no key to build a DPoP proof with, so a
		// DPoP-bound token it could never present is refused rather than
		// downgraded to Bearer use. RequireBearerTokenType also rejects a
		// token_type that is neither, which §6.1 makes REQUIRED.
		if err := receiverOid4vci.RequireBearerTokenType(token); err != nil {
			return nil, err
		}
		return token, nil
	}
	// With a client key both schemes are presentable. HAIP has already refused
	// anything but DPoP inside the transport ("Sender-constrained access token:
	// MUST support DPoP"); under Final an unknown token_type is still refused,
	// because §6.1 makes token_type REQUIRED and the wallet holds no other
	// scheme to present the token with.
	if !isDPoPAccessToken(token) && !strings.EqualFold(strings.TrimSpace(token.TokenType), "Bearer") {
		return nil, fmt.Errorf("token response returned token_type %q: %w", token.TokenType, ErrTokenTypeUnsupported)
	}
	return token, nil
}

// oid4vciDPoPNonceFor seeds the first token request proof with the RFC 9449
// §8.2 nonce the receiver already holds for that server, sparing the challenge
// round trip Section 8.2 exists to avoid.
func oid4vciDPoPNonceFor(flow *oid4vciFinalFlow, endpointURL string, useDPoP bool) string {
	if !useDPoP {
		return ""
	}
	parsed, err := url.Parse(endpointURL)
	if err != nil {
		return ""
	}
	server := strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
	return exportOID4VCIDPoPNonces(flow)[server]
}
