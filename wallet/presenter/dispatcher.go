package presenter

import (
	"fmt"
	"github.com/trustknots/vcknots/wallet/env"
	"net/url"

	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

type PresentationRequest = types.PresentationRequest

type PresentationDispatcher struct {
	plugins map[types.SupportedPresentationProtocol]types.Presenter
}

func NewPresentationDispatcher(options ...func(*PresentationDispatcher) error) (*PresentationDispatcher, error) {
	d := &PresentationDispatcher{
		plugins: make(map[types.SupportedPresentationProtocol]types.Presenter),
	}

	for _, option := range options {
		if err := option(d); err != nil {
			return nil, types.NewPresenterError(0, "", "configure", fmt.Errorf("failed to configure presentation dispatcher: %w", err))
		}
	}

	return d, nil
}

func WithDefaultConfig() func(d *PresentationDispatcher) error {
	return func(d *PresentationDispatcher) error {
		oid4vpReceiver := &oid4vp.Oid4vpPresenter{AllowHTTP: env.IsHTTPAllowed()}
		return d.registerPlugin(types.Oid4vp, oid4vpReceiver)
	}
}

func WithPlugin(protocol types.SupportedPresentationProtocol, plugin types.Presenter) func(*PresentationDispatcher) error {
	return func(d *PresentationDispatcher) error {
		return d.registerPlugin(protocol, plugin)
	}
}

func (d *PresentationDispatcher) registerPlugin(protocol types.SupportedPresentationProtocol, plugin types.Presenter) error {
	if plugin == nil {
		return types.NewPresenterError(protocol, "", "register", types.ErrNilPlugin)
	}
	d.plugins[protocol] = plugin
	return nil
}

func (d *PresentationDispatcher) getPlugin(protocol types.SupportedPresentationProtocol) (types.Presenter, error) {
	plugin, exists := d.plugins[protocol]
	if !exists {
		return nil, types.NewPresenterError(protocol, "", "get_plugin", types.ErrUnsupportedProtocol)
	}
	return plugin, nil
}

func (d *PresentationDispatcher) Present(protocol SupportedPresentationProtocol, endpoint url.URL, serializedPresentation []byte, request *PresentationRequest) (string, error) {
	if len(serializedPresentation) == 0 {
		return "", types.NewPresenterError(protocol, endpoint.String(), "present", types.ErrInvalidPresentation)
	}

	plugin, err := d.getPlugin(protocol)
	if err != nil {
		return "", err
	}

	redirectURI, err := plugin.Present(protocol, endpoint, serializedPresentation, request)
	if err != nil {
		return "", types.NewPresenterError(protocol, endpoint.String(), "present", err)
	}
	return redirectURI, nil
}

// PresentDCQL uses the registered plugin's multiple-query presentation capability.
func (d *PresentationDispatcher) PresentDCQL(protocol SupportedPresentationProtocol, endpoint url.URL, vpToken map[string][]string, request *PresentationRequest) (string, error) {
	plugin, err := d.getPlugin(protocol)
	if err != nil {
		return "", err
	}
	dcql, ok := plugin.(interface {
		PresentDCQL(types.SupportedPresentationProtocol, url.URL, map[string][]string, *PresentationRequest) (string, error)
	})
	if !ok {
		return "", types.NewPresenterError(protocol, endpoint.String(), "present_dcql", types.ErrUnsupportedProtocol)
	}
	redirectURI, err := dcql.PresentDCQL(protocol, endpoint, vpToken, request)
	if err != nil {
		return "", types.NewPresenterError(protocol, endpoint.String(), "present_dcql", err)
	}
	return redirectURI, nil
}

func (d *PresentationDispatcher) SubmitOID4VPFinalEncryptedAuthorizationResponse(endpoint url.URL, authzResponse map[string]any, metadata *oid4vp.VerifierMetadata) (string, error) {
	plugin, err := d.getPlugin(types.Oid4vp)
	if err != nil {
		return "", types.NewPresenterError(types.Oid4vp, endpoint.String(), "submit_final", err)
	}

	finalPresenter, ok := plugin.(interface {
		SubmitEncryptedAuthorizationResponse(url.URL, map[string]any, *oid4vp.VerifierMetadata) (string, error)
	})
	if !ok {
		return "", types.NewPresenterError(types.Oid4vp, endpoint.String(), "submit_final", types.ErrUnsupportedProtocol)
	}

	body, err := finalPresenter.SubmitEncryptedAuthorizationResponse(endpoint, authzResponse, metadata)
	if err != nil {
		return "", types.NewPresenterError(types.Oid4vp, endpoint.String(), "submit_final", err)
	}
	return body, nil
}

func (d *PresentationDispatcher) ParseRequestURI(uriString string) (*oid4vp.CredentialPresentationRequest, error) {
	// Determine protocol from URI (currently only OID4VP is supported)
	protocol := types.Oid4vp

	// Get appropriate plugin
	plugin, err := d.getPlugin(protocol)
	if err != nil {
		return nil, types.NewPresenterError(protocol, "", "parse_uri", err)
	}
	// Cast to OID4VP plugin and call ParsePresentationRequest
	if oid4vpPlugin, ok := plugin.(*oid4vp.Oid4vpPresenter); ok {
		req, err := oid4vpPlugin.ParsePresentationRequest(uriString)
		if err != nil {
			return nil, types.NewPresenterError(protocol, "", "parse_uri", err)
		}
		return req, nil
	}
	return nil, types.NewPresenterError(protocol, "", "parse_uri", types.ErrUnsupportedProtocol)
}

// ParseDraft24RequestURI parses a Presentation Exchange request using the registered Draft24 capability.
func (d *PresentationDispatcher) ParseDraft24RequestURI(uri string) (*oid4vp.CredentialPresentationRequest, error) {
	plugin, err := d.getPlugin(types.Oid4vp)
	if err != nil {
		return nil, err
	}
	draft, ok := plugin.(interface {
		ParseDraft24PresentationRequest(string) (*oid4vp.CredentialPresentationRequest, error)
	})
	if !ok {
		return nil, types.NewPresenterError(types.Oid4vp, "", "parse_draft24", types.ErrUnsupportedProtocol)
	}
	return draft.ParseDraft24PresentationRequest(uri)
}

// PresentDraft24 submits a legacy Presentation Exchange response through the registered capability.
func (d *PresentationDispatcher) PresentDraft24(protocol SupportedPresentationProtocol, endpoint url.URL, serialized []byte, submission types.PresentationSubmission, request *PresentationRequest) (string, error) {
	if len(serialized) == 0 {
		return "", types.NewPresenterError(protocol, endpoint.String(), "present_draft24", types.ErrInvalidPresentation)
	}
	plugin, err := d.getPlugin(protocol)
	if err != nil {
		return "", err
	}
	draft, ok := plugin.(interface {
		PresentDraft24(types.SupportedPresentationProtocol, url.URL, []byte, types.PresentationSubmission, *types.PresentationRequest) (string, error)
	})
	if !ok {
		return "", types.NewPresenterError(protocol, endpoint.String(), "present_draft24", types.ErrUnsupportedProtocol)
	}
	return draft.PresentDraft24(protocol, endpoint, serialized, submission, request)
}
