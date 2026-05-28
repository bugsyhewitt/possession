// Package record persists a scan's network phase (every variant + baseline
// request/response) to disk and replays it back into the detection pipeline
// without re-hitting the target (POST_V01 Item 7).
//
// The recording decouples the rate-limited, permission-sensitive, slow network
// phase from the fast, iterable detection phase. Once a target has been
// recorded, detection thresholds and evaluator changes can be tuned offline,
// and a target you only have permission to hit once can be re-scanned freely.
//
// Format: a single versioned JSON file. Responses are keyed by their
// model.Response.VariantID, which the replay engine stamps on every response
// and which is deterministic given the same input + matrix. On --replay the
// scan pipeline regenerates the plans normally (so endpoint attribution,
// calibration, and finding generation are unchanged) but substitutes saved
// responses for the live engine.Run, matching index-for-index by VariantID.
package record

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/bugsyhewitt/possession/internal/model"
)

// Filename is the canonical recording file name written inside the --record
// directory. A directory (rather than a bare file) keeps room for future
// sidecar artifacts without a format break.
const Filename = "recording.json"

// Version is the recording schema version. Bump on any breaking change to the
// on-disk shape; Load rejects unknown major versions.
const Version = "1"

// Recording is the on-disk shape of a captured scan network phase.
type Recording struct {
	Version string `json:"version"`
	// Tool is the possession version that produced the recording (informational).
	Tool string `json:"tool,omitempty"`
	// BaseURL is the matrix target, recorded for a human-friendly sanity check
	// and to warn loudly when a recording is replayed against a mismatched run.
	BaseURL string `json:"base_url,omitempty"`
	// RecordedAt is when the recording was written.
	RecordedAt time.Time `json:"recorded_at"`

	// Baseline holds the owner self-replay responses, keyed by VariantID.
	Baseline map[string]model.Response `json:"baseline"`
	// Variants holds the mutated-variant responses, keyed by VariantID.
	Variants map[string]model.Response `json:"variants"`
}

// New builds a Recording from the two aligned plans/response slices the scan
// pipeline already produces. The variant slices align index-for-index with
// their plan variants (the replay engine guarantees this); we key by the
// response's stamped VariantID so replay can match regardless of slice order.
func New(tool, baseURL string,
	baselineVariantIDs []string, baselineResponses []model.Response,
	variantIDs []string, variantResponses []model.Response) *Recording {

	r := &Recording{
		Version:    Version,
		Tool:       tool,
		BaseURL:    baseURL,
		RecordedAt: time.Now().UTC(),
		Baseline:   make(map[string]model.Response, len(baselineResponses)),
		Variants:   make(map[string]model.Response, len(variantResponses)),
	}
	fill(r.Baseline, baselineVariantIDs, baselineResponses)
	fill(r.Variants, variantIDs, variantResponses)
	return r
}

// fill keys each response by its preferred ID. The response's own VariantID is
// authoritative when present (the engine stamps it); the plan-derived id list is
// the fallback so recordings stay coherent even if a response left VariantID
// empty (e.g. a transport error before the engine set it).
func fill(dst map[string]model.Response, ids []string, resps []model.Response) {
	for i := range resps {
		key := resps[i].VariantID
		if key == "" && i < len(ids) {
			key = ids[i]
		}
		if key == "" {
			continue
		}
		dst[key] = resps[i]
	}
}

// Save writes the recording into dir/recording.json, creating dir if needed.
// The write is atomic (temp file + rename) so a crash mid-write never leaves a
// half-written recording that the next --replay can't parse.
func Save(dir string, r *Recording) error {
	if dir == "" {
		return fmt.Errorf("record: empty --record directory")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("record: mkdir %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("record: marshal: %w", err)
	}
	path := filepath.Join(dir, Filename)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("record: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("record: rename %s: %w", path, err)
	}
	return nil
}

// Load reads dir/recording.json and validates its schema version.
func Load(dir string) (*Recording, error) {
	if dir == "" {
		return nil, fmt.Errorf("record: empty --replay directory")
	}
	path := filepath.Join(dir, Filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("record: read %s: %w", path, err)
	}
	var r Recording
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("record: parse %s: %w", path, err)
	}
	if r.Version != Version {
		return nil, fmt.Errorf("record: %s has unsupported version %q (want %q)", path, r.Version, Version)
	}
	if r.Baseline == nil {
		r.Baseline = map[string]model.Response{}
	}
	if r.Variants == nil {
		r.Variants = map[string]model.Response{}
	}
	return &r, nil
}

// ResponsesFor returns the saved responses for the given variant IDs, in the
// same order as ids — exactly what the scan pipeline expects from engine.Run.
// Any id with no saved response yields a zero-value Response whose VariantID is
// set and Inconclusive is true (so the detection ladder treats it as a missing
// sample rather than a real bypass), and its id is appended to the returned
// missing slice for caller surfacing.
func (r *Recording) ResponsesFor(ids []string, baseline bool) (resps []model.Response, missing []string) {
	src := r.Variants
	if baseline {
		src = r.Baseline
	}
	resps = make([]model.Response, len(ids))
	for i, id := range ids {
		if got, ok := src[id]; ok {
			resps[i] = got
			continue
		}
		resps[i] = model.Response{VariantID: id, Inconclusive: true}
		missing = append(missing, id)
	}
	sort.Strings(missing)
	return resps, missing
}

// Counts reports how many baseline and variant responses the recording holds.
func (r *Recording) Counts() (baseline, variants int) {
	return len(r.Baseline), len(r.Variants)
}
