package model

import "net/http"

// Response records the result of replaying a Variant.
//
// Packet 2 produces Response values; Packet 3's detection evaluator
// consumes them. Body is retained in memory (capped at --max-body, see D12)
// so the evaluator can compare baseline vs variant content without re-issuing
// requests.
type Response struct {
	VariantID    string      `json:"variant_id"`
	Status       int         `json:"status"`
	Headers      http.Header `json:"headers,omitempty"`
	Body         []byte      `json:"body,omitempty"`
	Truncated    bool        `json:"truncated,omitempty"`
	BodySize     int64       `json:"body_size"`
	DurationMS   int64       `json:"duration_ms"`
	Err          string      `json:"err,omitempty"`
	Inconclusive bool        `json:"inconclusive,omitempty"`
}
