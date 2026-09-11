package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
)

func TestSelectedDisclosuresRespectRootCommitments(t *testing.T) {
	encode := func(parts ...any) (string, string) {
		raw, err := json.Marshal(parts)
		require.NoError(t, err)
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		digest := sha256.Sum256([]byte(encoded))
		return encoded, base64.RawURLEncoding.EncodeToString(digest[:])
	}
	root, rootHash := encode("root-salt", "given_name", "Taro")
	nested, nestedHash := encode("nested-salt", "given_name", "Another Person")
	array, arrayHash := encode("array-salt", "Array value")
	for _, tc := range []struct {
		name                      string
		payload                   map[string]any
		disclosures, claims, want []string
		wantError                 bool
	}{
		{name: "requested plaintext requires no disclosure", payload: map[string]any{"nationality": "JP", "_sd": []any{rootHash}}, disclosures: []string{root}, claims: []string{"nationality"}},
		{name: "root names do not disclose same-named nested claims", payload: map[string]any{"_sd": []any{rootHash}, "other": map[string]any{"_sd": []any{nestedHash}}}, disclosures: []string{root, nested}, claims: []string{"given_name"}, want: []string{root}},
		{name: "nested name cannot satisfy root request", payload: map[string]any{"other": map[string]any{"_sd": []any{nestedHash}}}, disclosures: []string{nested}, claims: []string{"given_name"}, wantError: true},
		{name: "uncommitted disclosure cannot satisfy request", payload: map[string]any{"_sd": []any{"wrong-digest"}}, disclosures: []string{root}, claims: []string{"given_name"}, wantError: true},
		{name: "duplicate root digest rejected", payload: map[string]any{"_sd": []any{rootHash, rootHash}}, disclosures: []string{root}, claims: []string{"given_name"}, wantError: true},
		{name: "duplicate root property rejected", payload: map[string]any{"_sd": []any{rootHash, nestedHash}}, disclosures: []string{root, nested}, claims: []string{"given_name"}, wantError: true},
		{name: "selective cannot overwrite plaintext", payload: map[string]any{"given_name": "Existing", "_sd": []any{rootHash}}, disclosures: []string{root}, claims: []string{"given_name"}, wantError: true},
		{name: "array element is not an object property", payload: map[string]any{"_sd": []any{arrayHash}}, disclosures: []string{array}, claims: []string{"given_name"}, wantError: true},
		{name: "no requested claims discloses none", payload: map[string]any{"_sd": []any{rootHash}}, disclosures: []string{root}},
		{name: "duplicate request selects once", payload: map[string]any{"_sd": []any{rootHash}}, disclosures: []string{root}, claims: []string{"given_name", "given_name"}, want: []string{root}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectTopLevelDisclosures(tc.payload, tc.disclosures, "sha-256", tc.claims)
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.ElementsMatch(t, tc.want, got)
		})
	}
}

func TestDeserializeCredentialKeepsNestedNamesOutOfRootClaims(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("dc+sd-jwt"))
	require.NoError(t, err)
	raw, err := json.Marshal([]any{"nested-salt", "given_name", "Jiro"})
	require.NoError(t, err)
	disclosure := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(disclosure))
	hash := base64.RawURLEncoding.EncodeToString(digest[:])
	for _, tc := range []struct {
		name      string
		payload   map[string]any
		want      string
		wantError bool
	}{
		{name: "nested value cannot overwrite plaintext", payload: map[string]any{"given_name": "Taro", "other": map[string]any{"_sd": []any{hash}}}, want: "Taro"},
		{name: "nested-only name is not a root property", payload: map[string]any{"other": map[string]any{"_sd": []any{hash}}}},
		{name: "uncommitted name is not a root property", payload: map[string]any{}},
		{name: "committed root name is reconstructed", payload: map[string]any{"_sd": []any{hash}}, want: "Jiro"},
		{name: "root disclosure cannot overwrite plaintext", payload: map[string]any{"given_name": "Taro", "_sd": []any{hash}}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.payload["iss"] = "https://issuer.example"
			tc.payload["vct"] = "urn:test:identity"
			signed, err := jwt.Signed(signer).Claims(tc.payload).Serialize()
			require.NoError(t, err)
			serializer, err := NewSdJwtVcSerializer()
			require.NoError(t, err)
			parsed, err := serializer.DeserializeCredential(credential.SDJwtVC, []byte(signed+"~"+disclosure+"~"))
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.want == "" {
				require.NotContains(t, *parsed.Claims, "given_name")
			} else {
				require.Equal(t, tc.want, (*parsed.Claims)["given_name"])
			}
		})
	}
}
