package detect

import (
	"github.com/bugsyhewitt/possession/internal/model"
)

// ClampBaselineSamples returns n clamped to [MinBaselineSamples,
// MaxBaselineSamples]. Used by the CLI when resolving --baseline-samples.
func ClampBaselineSamples(n int) int {
	if n < MinBaselineSamples {
		return MinBaselineSamples
	}
	if n > MaxBaselineSamples {
		return MaxBaselineSamples
	}
	return n
}

// CalibrationResult is the per-endpoint output of baseline calibration.
type CalibrationResult struct {
	Samples         int     // count of baseline samples actually fired (1..MaxBaselineSamples)
	Stability       float64 // mean pairwise similarity of normalized baseline bodies (1.0 when N=1)
	EffThreshold    float64 // per-endpoint similarity threshold for the verdict ladder
	Noisy           bool    // true ⇒ all verdicts on this endpoint cap at suspected
	BaselineBody    string  // normalized FIRST sample, used as the comparison anchor
	BaselineStatus  int     // status of the first sample
	BaselineCT      string  // content-type of the first sample (for normalization of variants)
	Skipped         bool    // true when N=1 (calibration skipped, DefaultThreshold applied)
	BaselineFailed  bool    // true when first sample's status is not 2xx ⇒ all variants inconclusive
	Notes           []EndpointNote // typed per-endpoint notes (D29)
}

// Calibrate computes the per-endpoint calibration from N owner-baseline
// responses. samples[0] is the comparison anchor (deterministic). When
// len(samples) == 1, calibration is skipped: stability=1.0, effThreshold
// = DefaultThreshold, a "calibration-skipped" note is recorded.
//
// When samples[0].Status is not 2xx, the endpoint's baseline is broken
// (often stale captured creds). BaselineFailed is set; the verdict ladder
// short-circuits every variant on that endpoint to inconclusive.
func Calibrate(samples []*model.Response) CalibrationResult {
	res := CalibrationResult{Samples: len(samples)}
	if len(samples) == 0 {
		res.BaselineFailed = true
		res.Notes = append(res.Notes, NewNote(NoteBaselineNot2xx, map[string]string{"reason": "no owner samples fired"}))
		res.EffThreshold = DefaultThreshold
		return res
	}
	first := samples[0]
	if first != nil {
		res.BaselineStatus = first.Status
		if first.Headers != nil {
			res.BaselineCT = first.Headers.Get("Content-Type")
		}
		res.BaselineBody = NormalizeBody(first.Body, res.BaselineCT)
	}
	if first == nil || first.Status < 200 || first.Status >= 300 {
		res.BaselineFailed = true
		res.Notes = append(res.Notes, NewNote(NoteBaselineNot2xx, nil))
		res.EffThreshold = DefaultThreshold
		return res
	}

	if len(samples) == 1 {
		res.Skipped = true
		res.Stability = 1.0
		res.EffThreshold = DefaultThreshold
		res.Notes = append(res.Notes, NewNote(NoteCalibrationSkipped, nil))
		return res
	}

	// Compute mean pairwise similarity of normalized bodies.
	norms := make([]string, len(samples))
	for i, s := range samples {
		if s == nil {
			continue
		}
		ct := ""
		if s.Headers != nil {
			ct = s.Headers.Get("Content-Type")
		}
		norms[i] = NormalizeBody(s.Body, ct)
	}
	var sum float64
	var pairs int
	for i := 0; i < len(norms); i++ {
		for j := i + 1; j < len(norms); j++ {
			sum += Similarity(norms[i], norms[j])
			pairs++
		}
	}
	if pairs == 0 {
		res.Stability = 1.0
	} else {
		res.Stability = sum / float64(pairs)
	}
	if res.Stability < NoisyEndpointThreshold {
		res.Noisy = true
		res.Notes = append(res.Notes, NewNote(NoteNoisyEndpoint, nil))
	}
	t := res.Stability - SimilarityMargin
	if t < MinThreshold {
		t = MinThreshold
	}
	if t > 1.0 {
		t = 1.0
	}
	res.EffThreshold = t
	return res
}
