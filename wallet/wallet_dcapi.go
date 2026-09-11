package wallet

import (
	"fmt"

	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
)

// oid4vpPresenter returns the registered OID4VP presenter plugin.
func (w *Wallet) oid4vpPresenter() (*oid4vp.Oid4vpPresenter, error) {
	for _, plugin := range w.presenter.Plugins() {
		if oid4vpPlugin, ok := plugin.(*oid4vp.Oid4vpPresenter); ok {
			return oid4vpPlugin, nil
		}
	}
	return nil, fmt.Errorf("no OID4VP presenter registered with the wallet")
}
