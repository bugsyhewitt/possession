package detect

import (
	"testing"

	"github.com/bugsyhewitt/possession/internal/model"
)

// TestClassifyConfidenceBand covers the pure band classifier across the
// decisive shapes: true BOLA (high conf + near-identical body), the
// 200-with-error-body wrapper (high conf but low similarity ⇒ capped low),
// the suspected mid-band, marker-reflection exemption, and the floor.
func TestClassifyConfidenceBand(t *testing.T) {
	cases := []struct {
		name            string
		confidence      float64
		similarity      float64
		markerReflected bool
		want            string
	}{
		{"true-bola-high", 0.92, 0.97, false, BandHigh},
		{"high-conf-but-divergent-body-is-low", 0.92, 0.40, false, BandLow},
		{"error-wrapper-200-low-sim-capped-low", 0.85, 0.20, false, BandLow},
		{"medium-conf-good-body", 0.60, 0.90, false, BandMedium},
		{"high-conf-partial-body-is-medium", 0.90, 0.70, false, BandMedium},
		{"marker-reflection-exempts-similarity", 0.95, 0.10, true, BandHigh},
		{"marker-reflection-medium-conf", 0.60, 0.05, true, BandMedium},
		{"low-conf-low-sim", 0.10, 0.10, false, BandLow},
		{"boundary-high-floor-exact", BandHighConfFloor, BandHighSimFloor, false, BandHigh},
		{"boundary-medium-floor-exact", BandMediumConfFloor, BandHighSimFloor, false, BandMedium},
		{"just-below-medium-floor", BandMediumConfFloor - 0.01, 0.99, false, BandLow},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ClassifyConfidenceBand(c.confidence, c.similarity, c.markerReflected)
			if got != c.want {
				t.Errorf("ClassifyConfidenceBand(%.2f, %.2f, %v) = %q, want %q",
					c.confidence, c.similarity, c.markerReflected, got, c.want)
			}
		})
	}
}

// TestBuildFinding_ConfidenceBand verifies the band is populated on the
// produced Finding and reflects the body-similarity gate end-to-end.
func TestBuildFinding_ConfidenceBand(t *testing.T) {
	ep := &model.Endpoint{Method: "GET", Host: "h", PathTemplate: "/x"}
	ownerBody := `{"name":"alice","items":["a","b","c","d","e","f","g","h"]}`
	norm := NormalizeBody([]byte(ownerBody), "application/json")
	cal := mkCal(norm, 200, false, false, false, 0.85)

	// 1) Variant body identical to baseline ⇒ high similarity ⇒ high band.
	vTrue := &model.Variant{ID: "v1", Mutation: model.Mutation{Type: "swap-identity", Class: "idor"}}
	rTrue := &model.Response{Status: 200, Body: []byte(ownerBody)}
	vvTrue := VariantVerdict{Verdict: VerdictBypass, Confidence: 0.92}
	fTrue := BuildFinding(ep, vTrue, rTrue, vvTrue, cal)
	if fTrue.ConfidenceBand != BandHigh {
		t.Errorf("true-bola: want band high got %q (sim=%.2f)", fTrue.ConfidenceBand, fTrue.Evidence.SimilarityScore)
	}

	// 2) 200 with a totally different (error-wrapper) body, despite a high
	//    numeric confidence, must NOT be high — the body diverges.
	vWrap := &model.Variant{ID: "v2", Mutation: model.Mutation{Type: "swap-identity", Class: "idor"}}
	rWrap := &model.Response{Status: 200, Body: []byte(`{"error":"forbidden"}`)}
	vvWrap := VariantVerdict{Verdict: VerdictBypass, Confidence: 0.92}
	fWrap := BuildFinding(ep, vWrap, rWrap, vvWrap, cal)
	if fWrap.ConfidenceBand == BandHigh {
		t.Errorf("error-wrapper: band must not be high, got %q (sim=%.2f)", fWrap.ConfidenceBand, fWrap.Evidence.SimilarityScore)
	}

	// 3) Owner-marker reflection note exempts the bulk-similarity gate.
	vMark := &model.Variant{ID: "v3", Mutation: model.Mutation{Type: "swap-identity", Class: "idor"}}
	rMark := &model.Response{Status: 200, Body: []byte(`{"x":"unrelated"}`)}
	vvMark := VariantVerdict{
		Verdict:    VerdictBypass,
		Confidence: 0.95,
		Notes:      []string{"reflectedOwner: variant body contains owner marker ⇒ bypass"},
	}
	fMark := BuildFinding(ep, vMark, rMark, vvMark, cal)
	if fMark.ConfidenceBand != BandHigh {
		t.Errorf("marker-reflection: want band high got %q", fMark.ConfidenceBand)
	}
}
