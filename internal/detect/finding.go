package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/bugsyhewitt/possession/internal/model"
)

// BuildFinding constructs a model.Finding for one variant that produced
// a bypass or suspected verdict. Class is derived from the variant's
// mutator type via MutatorClass (populating Variant.Mutation.Class as a
// side effect — Gate-D additive). Severity comes from SeverityByClass
// and is downgraded one notch for `suspected` verdicts (§5.3).
func BuildFinding(ep *model.Endpoint, v *model.Variant, r *model.Response, vv VariantVerdict, cal CalibrationResult) model.Finding {
	class := ""
	if v != nil {
		class = MutatorClass(v.Mutation.Type)
		// Populate the variant's Class field as the §6 additive change.
		v.Mutation.Class = class
	}

	severity := SeverityByClass[class]
	if vv.Verdict == VerdictSuspected {
		if d, ok := DowngradeSeverity[severity]; ok {
			severity = d
		}
	}
	asvs := append([]string(nil), ASVSByClass[class]...)

	epKey := endpointKey(ep)
	id := findingID(epKey, variantID(v), class)

	ident := ""
	if v != nil && v.Identity != nil {
		ident = v.Identity.Name
	}
	mut := ""
	if v != nil {
		mut = v.Mutation.Type
	}

	baselineStatus := cal.BaselineStatus
	variantStatus := 0
	variantSize := 0
	if r != nil {
		variantStatus = r.Status
		variantSize = len(r.Body)
	}
	baselineSize := len(cal.BaselineBody)

	// Compute similarity again for evidence — cheap and keeps Finding
	// self-contained. Could be threaded from judge() but the duplication
	// is trivial vs. the API noise.
	variantCT := ""
	if r != nil && r.Headers != nil {
		variantCT = r.Headers.Get("Content-Type")
	}
	var variantBody []byte
	if r != nil {
		variantBody = r.Body
	}
	variantNorm := NormalizeBody(variantBody, variantCT)
	sim := Similarity(cal.BaselineBody, variantNorm)

	notes := append([]string(nil), vv.Notes...)

	return model.Finding{
		ID:          id,
		Endpoint:    ep,
		Variant:     v,
		Class:       class,
		Verdict:     vv.Verdict,
		Confidence:  vv.Confidence,
		Severity:    severity,
		ASVS:        asvs,
		EndpointKey: epKey,
		VariantID:   variantID(v),
		Mutation:    mut,
		Identity:    ident,
		Evidence: model.Evidence{
			BaselineStatus:  baselineStatus,
			VariantStatus:   variantStatus,
			SimilarityScore: sim,
			SizeDelta:       variantSize - baselineSize,
			Notes:           notes,
		},
	}
}

// findingID is a deterministic 16-hex-char identifier:
//
//	sha256(endpoint_key + "|" + variant_id + "|" + class)[:16]
//
// Same inputs ⇒ same ID across runs.
func findingID(epKey, varID, class string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s", epKey, varID, class)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)[:16]
}

func endpointKey(ep *model.Endpoint) string {
	if ep == nil {
		return ""
	}
	return ep.Method + " " + ep.Host + ep.PathTemplate
}

func variantID(v *model.Variant) string {
	if v == nil {
		return ""
	}
	return v.ID
}
