package oid4vp

import "errors"

// ErrDCQLSelectionUnsatisfied reports that credentials chosen outside this
// library do not answer the DCQL query: a selected credential does not satisfy
// its credential query, the disclosed claims are not one of the claim sets that
// query offers (OID4VP 1.0 Section 6.3), a required credential_set has no fully
// answered option (Section 6.2), or a credential outside every answered option
// would be disclosed. A caller branches on it with errors.Is to tell a consent
// decision the request cannot accept from a transport or serialization failure.
var ErrDCQLSelectionUnsatisfied = errors.New("DCQL credential selection does not satisfy the query")
