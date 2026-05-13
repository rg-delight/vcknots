# OIDF Variant Inventory

This file records the OIDF conformance variants selected by the local VCKnots runner and the wallet-plan variant universe observed in the pinned `openid-conformance-suite` checkout.

The runner does not enumerate the full Cartesian product. It keeps a small set of executable variants for TDD and records artifacts for each run under `conformance/oidf/artifacts`.

## Selected Runner Variants

`vci-wallet-final`

```json
{
  "credential_format": "sd_jwt_vc",
  "fapi_profile": "vci",
  "vci_grant_type": "authorization_code",
  "vci_authorization_code_flow_variant": "issuer_initiated",
  "vci_credential_offer_variant": "by_value",
  "authorization_request_type": "simple",
  "client_auth_type": "client_attestation",
  "sender_constrain": "dpop",
  "fapi_request_method": "unsigned",
  "vci_credential_issuance_mode": "immediate",
  "vci_credential_encryption": "plain"
}
```

`vci-wallet-haip`

```json
{
  "credential_format": "sd_jwt_vc",
  "vci_authorization_code_flow_variant": "issuer_initiated",
  "vci_credential_offer_variant": "by_value"
}
```

`vp-wallet-final`

```json
{
  "vp_profile": "plain_vp",
  "credential_format": "sd_jwt_vc",
  "response_mode": "direct_post.jwt",
  "request_method": "request_uri_signed",
  "client_id_prefix": "x509_hash"
}
```

`vp-wallet-haip`

```json
{
  "credential_format": "sd_jwt_vc",
  "response_mode": "direct_post.jwt"
}
```

`vci-issuer-haip`

```json
{
  "credential_format": "sd_jwt_vc",
  "vci_authorization_code_flow_variant": "wallet_initiated"
}
```

`vp-verifier-haip`

```json
{
  "credential_format": "sd_jwt_vc",
  "response_mode": "direct_post.jwt"
}
```

## Wallet Variant Universe

### OID4VCI Wallet

Plan classes:

- `VCIWalletTestPlan`: `oid4vci-1_0-wallet-test-plan`
- `VCIWalletTestPlanHaip`: `oid4vci-1_0-wallet-haip-test-plan`

Variant parameters and observed values:

- `client_auth_type`: `none`, `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `mtls`, `client_attestation`
- `fapi_request_method`: `unsigned`, `signed_non_repudiation`
- `sender_constrain`: `mtls`, `dpop`
- `authorization_request_type`: `simple`, `rar`
- `fapi_profile`: `plain_fapi`, `openbanking_uk`, `consumerdataright_au`, `openbanking_brazil`, `connectid_au`, `cbuae`, `fapi_client_credentials_grant`, `vci`, `vci_haip`
- `vci_grant_type`: `authorization_code`, `pre_authorization_code`
- `vci_authorization_code_flow_variant`: `wallet_initiated`, `issuer_initiated`, `issuer_initiated_dc_api`
- `vci_credential_offer_variant`: `by_value`, `by_reference`
- `credential_format`: `sd_jwt_vc`, `mdoc`
- `vci_credential_issuance_mode`: `immediate`, `deferred`
- `vci_credential_encryption`: `plain`, `encrypted`

Important applicability constraints from the suite:

- `client_auth_type` values `none`, `client_secret_basic`, `client_secret_post`, and `client_secret_jwt` are not applicable for these wallet tests.
- `vci_credential_offer_variant` is hidden/not applicable for `vci_authorization_code_flow_variant=wallet_initiated`.
- `vci_authorization_code_flow_variant=issuer_initiated_dc_api` is not applicable with `fapi_profile=vci_haip`.
- `authorization_request_type=rar` is not applicable with `fapi_profile=vci_haip`.
- `vci_grant_type=pre_authorization_code` is not applicable with `fapi_profile=vci_haip`.

### OID4VP Wallet

Plan classes:

- `VP1FinalWalletTestPlan`: `oid4vp-1final-wallet-test-plan`
- `VP1FinalWalletTestPlanHaip`: `oid4vp-1final-wallet-haip-test-plan`

Variant parameters and observed values:

- `vp_profile`: `plain_vp`, `haip`
- `credential_format`: `sd_jwt_vc`, `iso_mdl`
- `client_id_prefix`: `decentralized_identifier`, `pre_registered`, `redirect_uri`, `web-origin`, `x509_san_dns`, `x509_hash`
- `response_mode`: `direct_post`, `direct_post.jwt`, `dc_api`, `dc_api.jwt`
- `request_method`: `url_query`, `request_uri_unsigned`, `request_uri_signed`, `request_uri_multisigned`

Important applicability constraints from the suite:

- `response_mode=direct_post` and `response_mode=dc_api` are not applicable with `vp_profile=haip`.
- `request_method=url_query` is not applicable with `response_mode=dc_api` or `response_mode=dc_api.jwt`.
- `request_method=request_uri_multisigned` is not applicable with `response_mode=direct_post` or `response_mode=direct_post.jwt`.
- `client_id_prefix=redirect_uri` and `client_id_prefix=web-origin` are not applicable with `request_method=request_uri_signed` or `request_method=request_uri_multisigned`.
- `VP1FinalWalletResponseUriNotClientId` is not applicable for `client_id_prefix=x509_san_dns`, `x509_hash`, `decentralized_identifier`, or `pre_registered`.
- Several negative modules have module-specific constraints; inspect the generated `plan.json` artifact for the exact module list after selecting a variant.

## Current Verified Module Counts

The counts below are for the selected runner variants, not every possible variant combination.

- `vci-wallet-final`: 4 modules.
- `vci-wallet-haip`: 9 modules.
- `vp-wallet-final`: 14 modules.
- `vp-wallet-haip`: 12 modules.
- `vci-issuer-haip`: 62 modules.
- `vp-verifier-haip`: 10 modules.

Revision note (2026-05-13): Added after confirming that the original HAIP-only runner was not enough to explain the Wallet Final 1.0 TDD surface. The selected variants above are executable against the local OIDF suite and currently classify as `harness_gap` until a VCKnots HTTP harness exists.
