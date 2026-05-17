package detect

import "fmt"

// NoteCode is the typed enum (D29) of endpoint-level notes the detection
// stage attaches to scan output. Replaces the prefix-tagged free strings
// ("calibration-skipped:", "noisy-endpoint:", …) Packet 3 carried over.
//
// Adding a new code: declare the constant, add a Render() case below, and
// add an entry to allEndpointNoteCodes (used by tests).
type NoteCode string

const (
	NoteCalibrationSkipped NoteCode = "calibration-skipped"
	NoteNoisyEndpoint      NoteCode = "noisy-endpoint"
	NoteBaselineNot2xx     NoteCode = "baseline-not-2xx"
	NoteRefreshFailed      NoteCode = "refresh-failed"
	NoteMinConfidence      NoteCode = "min-confidence"
	NoteCrossRankSwap      NoteCode = "cross-rank-swap"
)

// EndpointNote is a single typed annotation attached to an endpoint
// summary. Payload is optional structured data per code; Message is the
// pre-rendered human form so reporters that don't know about the enum
// (e.g. raw JSON consumers) still get a readable string.
type EndpointNote struct {
	Code    NoteCode          `json:"code"`
	Message string            `json:"message"`
	Payload map[string]string `json:"payload,omitempty"`
}

// Render returns the human-readable message for the note. Centralizing
// the strings here means tests and reporters get the exact same wording.
func (n EndpointNote) Render() string {
	if n.Message != "" {
		return n.Message
	}
	switch n.Code {
	case NoteCalibrationSkipped:
		return "calibration skipped (N=1 sample)"
	case NoteNoisyEndpoint:
		return "noisy endpoint (stability below threshold); bypass verdicts capped at suspected"
	case NoteBaselineNot2xx:
		return "baseline status not 2xx; all variants on this endpoint are inconclusive"
	case NoteRefreshFailed:
		ident := n.Payload["identity"]
		return fmt.Sprintf("refresh hook failed for identity %q; affected variants marked inconclusive", ident)
	case NoteMinConfidence:
		n2 := n.Payload["omitted"]
		return fmt.Sprintf("%s finding(s) omitted from array by --min-confidence (still counted in summary)", n2)
	case NoteCrossRankSwap:
		return "cross-rank swap-identity (actor outranks owner) — bypass capped at suspected per D28"
	default:
		return string(n.Code)
	}
}

// NewNote constructs a typed note. The renderer fills Message so consumers
// who only read the struct still see a human string.
func NewNote(code NoteCode, payload map[string]string) EndpointNote {
	n := EndpointNote{Code: code, Payload: payload}
	n.Message = n.Render()
	return n
}

// allEndpointNoteCodes lists every code; tests assert Render() returns
// non-empty for each so we don't add a code and forget the human form.
var allEndpointNoteCodes = []NoteCode{
	NoteCalibrationSkipped,
	NoteNoisyEndpoint,
	NoteBaselineNot2xx,
	NoteRefreshFailed,
	NoteMinConfidence,
	NoteCrossRankSwap,
}
