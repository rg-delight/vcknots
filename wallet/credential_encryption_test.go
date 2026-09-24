package wallet

import (
	"net/http"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func issuerMetadataWithEncryption(request bool, response bool, required bool) *receiverTypes.CredentialIssuerMetadata {
	metadata := &receiverTypes.CredentialIssuerMetadata{}
	if request {
		metadata.CredentialRequestEncryption = &receiverTypes.CredentialRequestEncryption{}
	}
	if response {
		metadata.CredentialResponseEncryption = &receiverTypes.CredentialResponseEncryption{EncryptionRequired: &required}
	}
	return metadata
}

// TestCredentialEncryptionPolicyFollowsIssuerByDefault pins the zero value: the
// specification default, where the Credential Issuer Metadata alone decides.
func TestCredentialEncryptionPolicyFollowsIssuerByDefault(t *testing.T) {
	policy := CredentialEncryptionPolicy{}

	key, err := policy.resolveCredentialResponseEncryptionKey(issuerMetadataWithEncryption(true, true, false), nil)
	require.NoError(t, err)
	require.NotNil(t, key, "an issuer advertising response encryption gets an ephemeral key")

	key, err = policy.resolveCredentialResponseEncryptionKey(issuerMetadataWithEncryption(false, false, false), nil)
	require.NoError(t, err)
	require.Nil(t, key, "an issuer advertising no response encryption is not asked for one")
}

// TestCredentialEncryptionPolicyKeepsTheCallersKey keeps a wallet that holds its
// own key material in control of it.
func TestCredentialEncryptionPolicyKeepsTheCallersKey(t *testing.T) {
	supplied, err := NewCredentialResponseEncryptionKey()
	require.NoError(t, err)

	key, err := CredentialEncryptionPolicy{}.resolveCredentialResponseEncryptionKey(
		issuerMetadataWithEncryption(true, true, false), &supplied)
	require.NoError(t, err)
	require.Equal(t, &supplied, key)
}

// TestCredentialEncryptionPolicyRequired refuses an issuance the issuer cannot
// encrypt, before anything is sent.
func TestCredentialEncryptionPolicyRequired(t *testing.T) {
	requestOnly := CredentialEncryptionPolicy{Request: CredentialEncryptionRequired}
	_, err := requestOnly.resolveCredentialResponseEncryptionKey(issuerMetadataWithEncryption(false, true, false), nil)
	require.ErrorIs(t, err, ErrCredentialEncryptionUnavailable)

	responseOnly := CredentialEncryptionPolicy{Response: CredentialEncryptionRequired}
	_, err = responseOnly.resolveCredentialResponseEncryptionKey(issuerMetadataWithEncryption(true, false, false), nil)
	require.ErrorIs(t, err, ErrCredentialEncryptionUnavailable)

	// §8.2 needs request encryption to carry the response key, so an issuer
	// offering only the response half cannot satisfy the policy either.
	_, err = responseOnly.resolveCredentialResponseEncryptionKey(issuerMetadataWithEncryption(false, true, false), nil)
	require.ErrorIs(t, err, ErrCredentialEncryptionUnavailable)

	key, err := responseOnly.resolveCredentialResponseEncryptionKey(issuerMetadataWithEncryption(true, true, false), nil)
	require.NoError(t, err)
	require.NotNil(t, key)
}

// TestCredentialEncryptionPolicyDisabled refuses rather than downgrades.
func TestCredentialEncryptionPolicyDisabled(t *testing.T) {
	disabled := CredentialEncryptionPolicy{Response: CredentialEncryptionDisabled}
	_, err := disabled.resolveCredentialResponseEncryptionKey(issuerMetadataWithEncryption(true, true, true), nil)
	require.ErrorIs(t, err, ErrCredentialEncryptionDisallowed)

	key, err := disabled.resolveCredentialResponseEncryptionKey(issuerMetadataWithEncryption(false, true, false), nil)
	require.NoError(t, err)
	require.Nil(t, key, "a disabled response encryption asks for no key")

	disabledRequest := CredentialEncryptionPolicy{Request: CredentialEncryptionDisabled}
	_, err = disabledRequest.resolveCredentialResponseEncryptionKey(issuerMetadataWithEncryption(true, false, false), nil)
	require.ErrorIs(t, err, ErrCredentialEncryptionDisallowed)
}

// TestReceiveOID4VCIFinalCredential_EncryptionPolicyRequiredFailsBeforeRequest
// pins that the policy is applied before the Credential Request is sent.
func TestReceiveOID4VCIFinalCredential_EncryptionPolicyRequiredFailsBeforeRequest(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.request()
	req.CredentialEncryption = CredentialEncryptionPolicy{Response: CredentialEncryptionRequired}

	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorIs(t, err, ErrCredentialEncryptionUnavailable)
	require.Equal(t, 0, fixture.credentialCalls)
}

// TestReceiveOID4VCIFinalCredential_EncryptionPolicyDisabledAgainstRequiringIssuer
// refuses an issuer that makes response encryption mandatory.
func TestReceiveOID4VCIFinalCredential_EncryptionPolicyDisabledAgainstRequiringIssuer(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.responseEncryption = true
		f.encryptionRequired = true
	})
	req := fixture.request()
	req.CredentialEncryption = CredentialEncryptionPolicy{Response: CredentialEncryptionDisabled}

	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorIs(t, err, ErrCredentialEncryptionDisallowed)
	require.Equal(t, 0, fixture.credentialCalls)
}

// TestReceiveOID4VCIFinalCredential_SkipNotification lets the process that
// actually stores the credential own the §11 report.
func TestReceiveOID4VCIFinalCredential_SkipNotification(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeNotification = true
	})
	req := fixture.request()
	req.SkipNotification = true

	result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.NoError(t, err)
	require.Equal(t, "notification-1", result.NotificationID, "the identifier still reaches the caller")
	require.Empty(t, fixture.notificationEvents)
}

// TestReceiveOID4VCIFinalCredential_RequireSingleCredential refuses a batch the
// issuance did not ask for, instead of storing a credential nobody requested.
func TestReceiveOID4VCIFinalCredential_RequireSingleCredential(t *testing.T) {
	secondCredential := ""
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.batchSize = 3
		secondCredential = f.issueCredential(f.additionalKey, map[string]string{"given_name": "Hanako"})
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credentials": []any{
					map[string]any{"credential": f.issuedCredential},
					map[string]any{"credential": secondCredential},
				},
			})
		}
	})
	req := fixture.request()
	req.RequireSingleCredential = true

	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorIs(t, err, ErrCredentialResponseMultipleCredentials)
}

// TestReceiveOID4VCIFinalCredential_RequireSingleCredentialRefusesLegacyMember
// refuses the singular `credential` member OpenID4VCI 1.0 §8.2 removed.
func TestReceiveOID4VCIFinalCredential_RequireSingleCredentialRefusesLegacyMember(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credential": f.issuedCredential})
		}
	})
	req := fixture.request()
	req.RequireSingleCredential = true

	_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
	require.ErrorIs(t, err, ErrCredentialResponseShape)
}

// The Final path reads the Credential Response in the strict §8.2 shape unless
// the caller opts in to the pre-Final one.
func TestReceiveOID4VCIFinalCredential_DraftResponseShapeIsOptIn(t *testing.T) {
	for name, payload := range map[string]func(*finalIssuanceFixture) map[string]any{
		"singular credential member": func(f *finalIssuanceFixture) map[string]any {
			return map[string]any{"credential": f.issuedCredential}
		},
		"bare string element": func(f *finalIssuanceFixture) map[string]any {
			return map[string]any{"credentials": []any{f.issuedCredential}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
				f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
					mockserver.JSONResponse(w, http.StatusOK, payload(f))
				}
			})
			_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(fixture.request())
			require.ErrorIs(t, err, ErrCredentialResponseShape)

			req := fixture.request()
			req.AllowDraftCredentialResponse = true
			result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
			require.NoError(t, err)
			require.Len(t, result.SavedCredentials, 1)
		})
	}
}

// A 200 Credential Response that carries neither credentials nor a
// transaction_id issues nothing; it is refused on every path, including the §9
// deferred poll and the pre-Final opt-in.
func TestReceiveOID4VCIFinalCredential_RefusesEmptySuccessResponse(t *testing.T) {
	for name, body := range map[string]map[string]any{
		"empty":                           {},
		"notification_id without content": {"notification_id": "notification-1"},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
				f.includeNotification = true
				f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
					mockserver.JSONResponse(w, http.StatusOK, body)
				}
			})
			req := fixture.request()
			req.AllowDraftCredentialResponse = true
			result, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
			require.ErrorIs(t, err, ErrCredentialResponseShape)
			require.Nil(t, result)
			require.Empty(t, fixture.notificationEvents)
		})
	}

	t.Run("deferred poll", func(t *testing.T) {
		fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
			f.includeDeferredEndpoint = true
			f.credentialHandler = func(w http.ResponseWriter, r *http.Request) {
				mockserver.JSONResponse(w, http.StatusAccepted, map[string]any{"transaction_id": "tx-1", "interval": 1})
			}
			f.deferredHandler = func(w http.ResponseWriter, r *http.Request) {
				mockserver.JSONResponse(w, http.StatusOK, map[string]any{})
			}
		})
		req := fixture.request()
		req.DeferredPollAttempts = 3
		_, err := fixture.wallet.ReceiveOID4VCIFinalCredential(req)
		require.ErrorIs(t, err, ErrCredentialResponseShape)
		require.Equal(t, 1, fixture.deferredCalls)
	})
}

// TestClampDeferredIntervalSeconds is the single cap an application that owns
// its own §9 polling schedule reads instead of choosing a second one.
func TestClampDeferredIntervalSeconds(t *testing.T) {
	require.Equal(t, int(MaxDeferredInterval/time.Second), ClampDeferredIntervalSeconds(86400, 0))
	require.Equal(t, 5, ClampDeferredIntervalSeconds(5, 0))
	require.Equal(t, 0, ClampDeferredIntervalSeconds(0, 0))
	require.Equal(t, -1, ClampDeferredIntervalSeconds(-1, 0))
	require.Equal(t, 10, ClampDeferredIntervalSeconds(30, 10*time.Second))
}

// TestKeyAttestationExpiresAtBindsTheAttestersLifetime keeps a reported expiry
// binding even when the attestation's own exp claim is later.
func TestKeyAttestationExpiresAtBindsTheAttestersLifetime(t *testing.T) {
	attesterKey := newPrivateJWKForFinalVCITest(t, "key-attester-expiry")
	holderKey := newPrivateJWKForFinalVCITest(t, "holder-expiry")
	attester := &StaticKeyAttester{Key: testKeyEntry(t, attesterKey), Issuer: "https://key-attester.example", Lifetime: time.Hour}
	request := KeyAttestationRequest{Keys: []jose.JSONWebKey{holderKey}, Audience: "https://issuer.example"}
	attestation, err := attester.KeyAttestation(t.Context(), request)
	require.NoError(t, err)

	policy := AttestationTrustPolicy{ResolveKey: func(AttestationJOSEHeader) (any, error) { return attesterKey.Public().Key, nil }}
	require.NoError(t, ValidateKeyAttestation(t.Context(), attestation, request, policy))

	attestation.ExpiresAt = time.Now().Add(-time.Minute)
	err = ValidateKeyAttestation(t.Context(), attestation, request, policy)
	require.ErrorIs(t, err, ErrKeyAttestationInvalid)
	require.ErrorContains(t, err, "expired")
}
