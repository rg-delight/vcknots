package wallet

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// storeAndNotifyOID4VCIFinalCredentials stores the credentials of a Credential
// Response and reports the outcome to the §11 Notification Endpoint. A failed
// notification never undoes the storage: it is returned in
// result.NotificationError, or joined to the storage error it reports.
func (w *Wallet) storeAndNotifyOID4VCIFinalCredentials(
	ctx context.Context,
	flow *oid4vciFinalFlow,
	token *receiverTypes.CredentialIssuanceAccessToken,
	clientKey jose.JSONWebKey,
	credentialResponse *receiverTypes.CredentialResponse,
) (*OID4VCIFinalReceiveResult, error) {
	issuerMetadata := flow.issuerMetadata
	result := pendingOID4VCIFinalResult(issuerMetadata, flow.credentialConfigurationID, token, credentialResponse)
	notify := func(event OID4VCINotificationEvent) *OID4VCINotificationError {
		if flow.policy.skipNotification {
			return nil
		}
		if err := notifyOID4VCIFinalCredential(ctx, flow.receiver, flow.signer, issuerMetadata, token, clientKey, result.NotificationID, event); err != nil {
			return &OID4VCINotificationError{Event: event, Err: err}
		}
		return nil
	}
	savedCredentials, storeErr := w.storeOID4VCIFinalCredentialResponseBatch(ctx, credentialResponse, issuerMetadata, flow.credentialConfigurationID, flow.holderKeys)
	if storeErr != nil {
		if notifyErr := notify(OID4VCINotificationCredentialFailure); notifyErr != nil {
			return nil, errors.Join(storeErr, notifyErr)
		}
		return nil, storeErr
	}
	result.SavedCredentials = savedCredentials
	// §11: credential_accepted is sent only after the credentials were stored.
	result.NotificationError = notify(OID4VCINotificationCredentialAccepted)
	return result, nil
}

func oid4vciFinalCredentialRequestBodyFactory(
	ctx context.Context,
	flow *oid4vciFinalFlow,
	credentialIdentifier *string,
	encryptionParams map[string]any,
) receiverTypes.CredentialRequestBodyFactory {
	issuerMetadata := flow.issuerMetadata
	signingAlgValues := proofSigningAlgValues(flow.credentialConfiguration)
	return func(cNonce string) ([]byte, string, error) {
		keyAttestationJWT := ""
		if flow.keyAttestation != nil {
			request := KeyAttestationRequest{
				Keys:     flow.holderKeys,
				Nonce:    cNonce,
				Audience: issuerMetadata.CredentialIssuer,
			}
			attestation := flow.suppliedKeyAttestation
			switch {
			case attestation != nil:
				// Appendix D attestations are single use and bound to the
				// c_nonce they were minted for. This factory is called a second
				// time only after §8.3.1.2 "invalid_nonce", and re-sending the
				// first attestation under a fresh nonce would just be refused
				// again, so the flow stops and lets the caller sign once more.
				if cNonce != flow.suppliedKeyAttestationNonce {
					return nil, "", fmt.Errorf(
						"the credential endpoint issued a fresh c_nonce after the key attestation was signed: %w",
						ErrKeyAttestationNonceStale)
				}
			case flow.keyAttestation.provider != nil:
				provided, err := flow.keyAttestation.provider.KeyAttestation(ctx, request)
				if err != nil {
					return nil, "", fmt.Errorf("failed to obtain key attestation: %w", err)
				}
				attestation = provided
			default:
				return nil, "", fmt.Errorf(
					"no key attestation provider is configured and the request carries none: %w",
					ErrKeyAttestationRequired)
			}
			if err := ValidateKeyAttestation(ctx, attestation, request, flow.keyAttestation.policy); err != nil {
				return nil, "", err
			}
			if err := requireListedProofAlgorithm("key attestation", attestation.JWT, signingAlgValues); err != nil {
				return nil, "", err
			}
			keyAttestationJWT = attestation.JWT
		}
		proofOptions := receiverTypes.ProofOptions{
			Audience:         issuerMetadata.CredentialIssuer,
			Nonce:            cNonce,
			KeyAttestation:   keyAttestationJWT,
			SigningAlgValues: signingAlgValues,
		}
		proofs := make([]string, 0, len(flow.holderKeys))
		for _, key := range flow.holderKeys {
			proof, err := flow.signer.CreateCredentialRequestJWTProofWithOptions(key, proofOptions)
			if err != nil {
				return nil, "", fmt.Errorf("failed to create credential request proof: %w", err)
			}
			if err := requireListedProofAlgorithm("key proof", proof, signingAlgValues); err != nil {
				return nil, "", err
			}
			proofs = append(proofs, proof)
		}
		payload := map[string]any{"proofs": map[string]any{"jwt": proofs}}
		// §6.2/§8.2: when the token response carries credential_identifiers the
		// credential_identifier member is sent instead of
		// credential_configuration_id.
		if credentialIdentifier != nil && *credentialIdentifier != "" {
			payload["credential_identifier"] = *credentialIdentifier
		} else {
			payload["credential_configuration_id"] = flow.credentialConfigurationID
		}
		if encryptionParams != nil {
			payload["credential_response_encryption"] = encryptionParams
		}
		body, contentType, err := flow.receiver.EncodeCredentialRequest(payload, issuerMetadata)
		if err != nil {
			return nil, "", fmt.Errorf("failed to encode credential request: %w", err)
		}
		return body, contentType, nil
	}
}

// proofSigningAlgValues reads the jwt proof type's
// proof_signing_alg_values_supported (§12.2.4). An empty result imposes no
// constraint.
func proofSigningAlgValues(config receiverTypes.CredentialConfiguration) []jose.SignatureAlgorithm {
	if config.ProofTypesSupported == nil {
		return nil
	}
	jwtProof, ok := (*config.ProofTypesSupported)["jwt"]
	if !ok {
		return nil
	}
	return jwtProof.ProofSigningAlgValuesSupported
}

// requireJWTProofType refuses a Credential Configuration whose
// proof_types_supported omits jwt, the only key proof this wallet produces.
// A configuration without proof_types_supported requires no proof (§12.2.4).
func requireJWTProofType(configurationID string, config receiverTypes.CredentialConfiguration) error {
	if config.ProofTypesSupported == nil {
		return nil
	}
	if _, ok := (*config.ProofTypesSupported)["jwt"]; ok {
		return nil
	}
	types := make([]string, 0, len(*config.ProofTypesSupported))
	for name := range *config.ProofTypesSupported {
		types = append(types, name)
	}
	slices.Sort(types)
	return fmt.Errorf("credential configuration %q lists proof types %v: %w", configurationID, types, ErrProofTypeUnsupported)
}

// requireListedProofAlgorithm applies Appendix F.1: the alg header of the key
// proof and of its key_attestation MUST be one of
// proof_signing_alg_values_supported. It holds a signer that ignored the list
// to the issuer's metadata before the request is sent.
func requireListedProofAlgorithm(what string, token string, supported []jose.SignatureAlgorithm) error {
	if len(supported) == 0 {
		return nil
	}
	header, err := AttestationJOSEHeaderFromJWT(token)
	if err != nil {
		return fmt.Errorf("%s is malformed: %w", what, err)
	}
	if !slices.Contains(supported, jose.SignatureAlgorithm(header.Algorithm)) {
		return fmt.Errorf("%s is signed with %q, not one of proof_signing_alg_values_supported %v: %w", what, header.Algorithm, supported, ErrProofAlgorithmNotSupported)
	}
	return nil
}

func oid4vciFinalDpopProofFactory(signer receiverTypes.OID4VCIFinalSigner, clientKey jose.JSONWebKey, endpoint common.URIField, accessToken string) receiverTypes.DPoPProofFactory {
	return func(nonce string) (string, error) {
		return signer.CreateDpopProof(clientKey, http.MethodPost, endpoint.String(), nonce, accessToken)
	}
}

// decodeOID4VCIFinalCredentialResponse decodes a Credential or Deferred
// Credential Response for flow: one credential per key proof, the pre-Final
// shape only when the caller opted in.
func decodeOID4VCIFinalCredentialResponse(flow *oid4vciFinalFlow, raw *receiverTypes.CredentialEndpointHTTPResponse, key *jose.JSONWebKey) (*receiverTypes.CredentialResponse, error) {
	maxCredentials := len(flow.holderKeys)
	if flow.policy.requireSingleCredential {
		maxCredentials = 1
	}
	response, err := DecodeOID4VCIFinalCredentialResponse(raw.Body, raw.ContentType, CredentialResponseDecodeOptions{
		DecryptionKey: key,
		shape: credentialResponseShape{
			maxCredentials: maxCredentials,
			allowDraft:     flow.policy.allowDraftCredentialResponse,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to decode credential response: %w", err)
	}
	return response, nil
}

func resolveOID4VCIFinalHolderKeys(req OID4VCIFinalReceiveRequest, required bool) ([]jose.JSONWebKey, error) {
	if req.HolderKey.Key == nil {
		if required {
			return nil, fmt.Errorf("holder key is required")
		}
		// The §5 authorization stage signs nothing with a holder key: the key
		// proofs of §8.2.1.1 and the Appendix D attestation are built after the
		// token exchange. A wallet whose holder key is created once the browser
		// comes back therefore starts an authorization without one.
		if len(req.AdditionalHolderKeys) > 0 {
			return nil, fmt.Errorf("additional holder keys were supplied without a holder key")
		}
		return nil, nil
	}
	keys := make([]jose.JSONWebKey, 0, 1+len(req.AdditionalHolderKeys))
	keys = append(keys, req.HolderKey)
	for index, key := range req.AdditionalHolderKeys {
		if key.Key == nil {
			return nil, fmt.Errorf("additional holder key %d is missing a key", index)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// oid4vciKeyAttestationPlan records that a key attestation must be attached to
// every credential request proof for this issuance.
type oid4vciKeyAttestationPlan struct {
	// provider is nil when the caller mints the attestation out of process
	// (OID4VCIFinalReceiveRequest.ExternalKeyAttestation).
	provider KeyAttestationProvider
	// policy authenticates what the provider returns: the attester signature
	// and, when anchors are configured, the x5c chain.
	policy AttestationTrustPolicy
	// required records that the issuer's Credential Configuration advertises
	// proof_types_supported.jwt.key_attestations_required, as opposed to the
	// wallet volunteering an attestation through IncludeKeyAttestation.
	required bool
}

// planOID4VCIKeyAttestation decides whether a key attestation is needed. It
// fails before any request is sent when the issuer requires one but the wallet
// has no provider, naming HAIP §4.5.1 under the HAIP profile.
//
// external is the caller's declaration that it mints the attestation itself, at
// the interruption between AuthorizeOID4VCIFinalToken and
// RequestOID4VCIFinalCredential. It only moves the fail-closed point: without a
// provider the plan is still made, and the credential stage refuses to send a
// request with no attestation (ErrKeyAttestationRequired).
func (w *Wallet) planOID4VCIKeyAttestation(metadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string, include bool, external bool) (*oid4vciKeyAttestationPlan, error) {
	required := IssuerRequiresKeyAttestation(metadata, credentialConfigurationID)
	if required && w.keyAttestation == nil && !external {
		if w.profile.IsHAIP() {
			return nil, fmt.Errorf("HAIP §4.5.1 requires wallets to support key attestations: the issuer requires a key attestation but no KeyAttestation provider is configured")
		}
		return nil, fmt.Errorf("the issuer requires a key attestation but no KeyAttestation provider is configured")
	}
	if !required && !include {
		return nil, nil
	}
	if w.keyAttestation == nil && !external {
		return nil, nil
	}
	return &oid4vciKeyAttestationPlan{
		provider: w.keyAttestation,
		policy:   w.attestationPolicyFor(w.keyAttestation),
		required: required,
	}, nil
}

// IssuerRequiresKeyAttestation reports whether the selected credential
// configuration advertises proof_types_supported.jwt.key_attestations_required
// (OpenID4VCI 1.0 Appendix D). Presence of the object, even empty, is the
// signal.
func IssuerRequiresKeyAttestation(metadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string) bool {
	if metadata == nil || metadata.CredentialConfigurationSupported == nil {
		return false
	}
	config, ok := metadata.CredentialConfigurationSupported[credentialConfigurationID]
	if !ok || config.ProofTypesSupported == nil {
		return false
	}
	jwtProof, ok := (*config.ProofTypesSupported)["jwt"]
	if !ok {
		return false
	}
	return jwtProof.KeyAttestationsRequired != nil
}

// clientAttestationProvider resolves the provider for this request. A request
// AttesterKey is only used as a compatibility fallback when no provider is
// configured.
func (w *Wallet) clientAttestationProvider(req OID4VCIFinalReceiveRequest) (ClientAttestationProvider, error) {
	if w.clientAttestation != nil {
		return w.clientAttestation, nil
	}
	if req.AttesterKey.Key == nil {
		return nil, nil
	}
	if strings.TrimSpace(req.AttesterIssuer) == "" {
		return nil, fmt.Errorf("attester issuer is required when attester key is provided")
	}
	return &StaticClientAttester{Key: req.AttesterKey, Issuer: req.AttesterIssuer}, nil
}

func (w *Wallet) createOID4VCIAttestationHeaders(ctx context.Context, receiver receiverTypes.OID4VCIFinalTransport, req OID4VCIFinalReceiveRequest, authMetadata *receiverTypes.AuthorizationServerMetadata, authorizationServerIssuer string) (receiverTypes.OAuthClientAttestationHeaders, string, error) {
	provider, err := w.clientAttestationProvider(req)
	if err != nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", err
	}
	if provider == nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", nil
	}
	if authorizationServerIssuer == "" {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", fmt.Errorf("authorization server issuer is required for client attestation")
	}

	attestationRequest := ClientAttestationRequest{
		ClientID:            req.ClientID,
		ClientKey:           req.ClientKey,
		AuthorizationServer: authorizationServerIssuer,
	}
	// HAIP §4.4.1: authenticate the provider result before any request carrying
	// the attestation leaves the wallet. ValidateClientAttestation is the one
	// path the wallet uses: it establishes who signed the attestation (the x5c
	// leaf, the configured resolver, or the bundled attester's own key) and
	// only then checks the binding to this wallet instance.
	attestation, err := provider.ClientAttestation(ctx, attestationRequest)
	if err != nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", fmt.Errorf("failed to obtain client attestation: %w", err)
	}
	if err := ValidateClientAttestation(ctx, attestation, attestationRequest, w.attestationPolicyFor(provider)); err != nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", err
	}

	attestationChallenge := ""
	if authMetadata.ChallengeEndpoint != nil {
		challenge, err := receiver.FetchClientAttestationChallenge(ctx, *authMetadata.ChallengeEndpoint)
		if err != nil {
			return receiverTypes.OAuthClientAttestationHeaders{}, "", fmt.Errorf("failed to fetch client attestation challenge: %w", err)
		}
		attestationChallenge = challenge.AttestationChallenge
	}

	clientAttestationPop, err := w.oid4vciFinalSigner(receiver).CreateClientAttestationPop(req.ClientKey, req.ClientID, authorizationServerIssuer, attestationChallenge, 5*time.Minute)
	if err != nil {
		return receiverTypes.OAuthClientAttestationHeaders{}, "", err
	}
	return receiverTypes.OAuthClientAttestationHeaders{
		ClientAttestation:    attestation.JWT,
		ClientAttestationPop: clientAttestationPop,
	}, attestationChallenge, nil
}

func (w *Wallet) storeOID4VCIFinalCredentialResponse(ctx context.Context, response *receiverTypes.CredentialResponse, issuerMetadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string, holderKey *jose.JSONWebKey) ([]*SavedCredential, error) {
	var holderKeys []jose.JSONWebKey
	if holderKey != nil {
		holderKeys = append(holderKeys, *holderKey)
	}
	return w.storeOID4VCIFinalCredentialResponseBatch(ctx, response, issuerMetadata, credentialConfigurationID, holderKeys)
}

// storeOID4VCIFinalCredentialResponseBatch verifies each returned credential
// against the holder key at the same index (§14.6 batch order) and stores
// nothing when any credential fails acceptance.
func (w *Wallet) storeOID4VCIFinalCredentialResponseBatch(ctx context.Context, response *receiverTypes.CredentialResponse, issuerMetadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string, holderKeys []jose.JSONWebKey) ([]*SavedCredential, error) {
	if response == nil {
		return nil, fmt.Errorf("credential response is nil")
	}
	mimeType := mimeTypeForCredentialConfiguration(issuerMetadata, credentialConfigurationID)
	flavor, err := (&credstoreTypes.CredentialEntry{MimeType: mimeType}).SerializationFlavor()
	if err != nil {
		return nil, fmt.Errorf("unsupported credential serialization flavor: %w", err)
	}
	values := []any{}
	if response.Credential != nil {
		values = append(values, response.Credential)
	}
	values = append(values, response.Credentials...)
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: credential response carries no credentials", ErrCredentialResponseShape)
	}
	if len(holderKeys) > 0 && len(values) > len(holderKeys) {
		return nil, fmt.Errorf("credential response returned %d credentials but only %d holder keys were supplied", len(values), len(holderKeys))
	}

	saved := make([]*SavedCredential, 0, len(values))
	usedKeys := make([]bool, len(holderKeys))
	for _, value := range values {
		raw, err := rawCredentialBytes(value)
		if err != nil {
			return nil, err
		}
		// OpenID4VCI 1.0 §8.3 does not promise that the credentials array
		// follows the order of the proofs, so each credential is matched to the
		// holder key its cnf names; every supplied key may be used at most once.
		holderKey, err := matchBatchHolderKey(raw, flavor, holderKeys, usedKeys)
		if err != nil {
			return nil, err
		}
		// A credential arriving on the Final/HAIP issuance path has an issuer
		// identity the flow can check, so Config.CredentialAcceptance is
		// mandatory here rather than optional as on the Draft-13 path.
		parsedCredential, verification, err := w.verifyCredentialForAcceptanceContext(ctx, raw, flavor, holderKey, true)
		if err != nil {
			return nil, fmt.Errorf("failed to verify credential: %w", err)
		}
		entry := credstoreTypes.CredentialEntry{
			Id:         uuid.New().String(),
			ReceivedAt: time.Now(),
			Raw:        raw,
			MimeType:   mimeType,
		}
		saved = append(saved, &SavedCredential{
			Credential:   parsedCredential,
			Entry:        &entry,
			Verification: verification,
		})
	}

	// A storeless wallet verified the credentials and hands them back in the
	// result; the process that owns the durable state persists them
	// (Config.Storeless).
	if w.credStore != nil {
		for _, savedCredential := range saved {
			if err := w.credStore.SaveCredentialEntry(*savedCredential.Entry, credstoreTypes.SupportedCredStoreTypes(0)); err != nil {
				return nil, fmt.Errorf("failed to save credential entry: %w", err)
			}
		}
	}
	return saved, nil
}

// matchBatchHolderKey selects the holder key whose RFC 7638 thumbprint equals
// the credential's cnf.jwk. A credential without cnf takes the first unused key
// (the acceptance rules then decide whether that is allowed); a cnf that names
// none of the supplied keys, or a key that was already consumed, is an error.
func matchBatchHolderKey(raw []byte, flavor credential.SupportedSerializationFlavor, holderKeys []jose.JSONWebKey, usedKeys []bool) (*jose.JSONWebKey, error) {
	if len(holderKeys) == 0 {
		return nil, nil
	}
	claimed, err := credentialConfirmationKey(raw, flavor)
	if err != nil {
		return nil, err
	}
	if claimed == nil {
		for index := range holderKeys {
			if !usedKeys[index] {
				usedKeys[index] = true
				publicKey := holderKeys[index].Public()
				return &publicKey, nil
			}
		}
		return nil, fmt.Errorf("credential response returned more credentials than holder keys")
	}
	claimedThumbprint, err := claimed.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("cnf jwk thumbprint failed: %w", err)
	}
	for index := range holderKeys {
		publicKey := holderKeys[index].Public()
		thumbprint, err := publicKey.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("holder key thumbprint failed: %w", err)
		}
		if !bytes.Equal(thumbprint, claimedThumbprint) {
			continue
		}
		if usedKeys[index] {
			return nil, fmt.Errorf("credential response bound two credentials to the same holder key")
		}
		usedKeys[index] = true
		return &publicKey, nil
	}
	return nil, fmt.Errorf("credential is bound to a holder key that was not part of the request")
}

// credentialConfirmationKey reads cnf.jwk from the issuer-signed JWT payload
// without verifying anything; nil when the credential carries no cnf.
func credentialConfirmationKey(raw []byte, flavor credential.SupportedSerializationFlavor) (*jose.JSONWebKey, error) {
	parts := strings.Split(issuerSignedJWT(flavor, raw), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("issuer JWT must have exactly three parts")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("issuer JWT payload is not base64url: %w", err)
	}
	var payload struct {
		Cnf *struct {
			JWK json.RawMessage `json:"jwk"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("issuer JWT payload is not JSON: %w", err)
	}
	if payload.Cnf == nil || len(payload.Cnf.JWK) == 0 {
		return nil, nil
	}
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(payload.Cnf.JWK); err != nil {
		return nil, fmt.Errorf("cnf jwk is invalid: %w", err)
	}
	return &key, nil
}

func rawCredentialBytes(value any) ([]byte, error) {
	switch credentialValue := value.(type) {
	case string:
		return []byte(credentialValue), nil
	case []byte:
		return credentialValue, nil
	case map[string]any:
		// OpenID4VCI 1.0 §8.3: "credentials" is an array of objects, each with
		// a "credential" member carrying the issued credential (a string for
		// JWT-based formats or a JSON object). Unwrap that envelope; any other
		// object is the credential itself.
		if inner, ok := credentialValue["credential"]; ok && len(credentialValue) == 1 {
			return rawCredentialBytes(inner)
		}
		raw, err := json.Marshal(credentialValue)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal credential value: %w", err)
		}
		return raw, nil
	default:
		raw, err := json.Marshal(credentialValue)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal credential value: %w", err)
		}
		return raw, nil
	}
}

func mimeTypeForCredentialConfiguration(issuerMetadata *receiverTypes.CredentialIssuerMetadata, credentialConfigurationID string) string {
	if issuerMetadata != nil {
		if config, ok := issuerMetadata.CredentialConfigurationSupported[credentialConfigurationID]; ok {
			switch config.Format {
			case "dc+sd-jwt", "vc+sd-jwt":
				return string(credential.SDJwtVC)
			case "jwt_vc_json", "jwt_vc", "vc+jwt":
				return string(credential.JwtVc)
			}
		}
	}
	return string(credential.JwtVc)
}
