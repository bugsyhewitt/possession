package model

// Endpoint is a deduplicated logical endpoint, identified by the tuple
// (Method, Host, PathTemplate). The concrete CapturedRequests that mapped
// to it are retained as Samples so that replay can pick a representative
// when issuing variants.
type Endpoint struct {
	Method       string
	Host         string
	PathTemplate string
	Samples      []*CapturedRequest
}
