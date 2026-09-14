package wallet

import (
	"fmt"

	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
)

// PresentCredentialToDCAPI answers an OpenID4VP 1.0 DC API invocation (Appendix
// A) without any HTTP call. It parses and authenticates the platform request,
// selects credentials with the same DCQL machinery as the redirect flows, sets
// the Key Binding JWT audience to origin:<origin> (Appendix A.4), and returns
// the DCAPIResponse object for the platform. Optional serialization options are
// passed through to the serializer; the first non-nil option wins.
func (w *Wallet) PresentCredentialToDCAPI(invocation oid4vp.DCAPIInvocation, key IKeyEntry, options ...serializerTypes.SerializePresentationOptions) (*oid4vp.DCAPIResponse, error) {
	presenter, err := w.oid4vpPresenter()
	if err != nil {
		return nil, err
	}
	request, err := presenter.ParseDCAPIRequest(invocation)
	if err != nil {
		return nil, err
	}
	if err := validateTransactionDataHolderBinding(request); err != nil {
		return nil, err
	}

	var serializeOptions serializerTypes.SerializePresentationOptions
	for _, option := range options {
		if option != nil {
			serializeOptions = option
			break
		}
	}

	// Appendix A.4: the response audience is origin:<origin>, not client_id.
	// applyOID4VPRequestOptions copies client_id into the KB-JWT audience, so
	// present a shallow copy whose effective client identifier is the audience.
	presented := request
	if request.ResponseAudience != "" && request.ClientID != request.ResponseAudience {
		copied := *request
		oauth := *request.OAuthAuthzRequest
		oauth.ClientID = request.ResponseAudience
		copied.OAuthAuthzRequest = &oauth
		presented = &copied
	}

	vpToken, err := w.buildDCQLVPToken(presented, key, serializeOptions)
	if err != nil {
		return nil, err
	}
	return presenter.BuildDCAPIResponse(request, vpToken)
}

// oid4vpPresenter returns the registered OID4VP presenter plugin.
func (w *Wallet) oid4vpPresenter() (*oid4vp.Oid4vpPresenter, error) {
	for _, plugin := range w.presenter.Plugins() {
		if oid4vpPlugin, ok := plugin.(*oid4vp.Oid4vpPresenter); ok {
			return oid4vpPlugin, nil
		}
	}
	return nil, fmt.Errorf("no OID4VP presenter registered with the wallet")
}
