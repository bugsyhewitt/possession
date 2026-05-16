package model

// Endpoint is a deduplicated logical endpoint, identified by the tuple
// (Method, Host, PathTemplate). The concrete CapturedRequests that mapped
// to it are retained as Samples so that replay can pick a representative
// when issuing variants.
//
// OwnerIdentity and OwnerAttribution are populated by the Packet-3 detection
// stage (D17). OwnerIdentity is the matrix Identity whose credentials match
// the captured request; OwnerAttribution describes how the match was made
// (`exact-bearer`, `exact-cookie`, `exact-header`, `basic-username`,
// `fallback-highest-rank`, or `ambiguous`). Both are zero-valued before
// detection runs.
type Endpoint struct {
	Method       string
	Host         string
	PathTemplate string
	Samples      []*CapturedRequest

	OwnerIdentity    *Identity `json:"-"`
	OwnerAttribution string    `json:"-"`
}
