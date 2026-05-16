// Package detect will compare variant responses against baselines and emit
// model.Findings.
//
// Packet 1 declares only the extension seam: the Evaluator interface, which
// Packet 3 will widen and implement.
package detect

// Evaluator compares a variant response against a baseline response and
// returns a *model.Finding if an authz issue is detected, or nil otherwise.
//
// TODO(packet-3): full signature lands once the Response type is introduced
// in Packet 2. The interface is intentionally empty in Packet 1; its
// presence documents the extension seam.
type Evaluator interface {
	// Evaluate(baseline, variant *replay.Response) (*model.Finding, error)
}
