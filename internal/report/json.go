package report

import (
	"encoding/json"
	"io"

	"github.com/bugsyhewitt/possession/internal/model"
)

// JSONReporter emits the RunResult as deterministic, 2-space-indented
// JSON. Field order is fixed by struct declaration order in
// model.RunResult — running this reporter twice on identical input
// must produce byte-identical output (D26). That makes the format a
// stable contract for downstream tools (Pho3nix) that diff or hash it.
type JSONReporter struct{}

// Name returns "json".
func (JSONReporter) Name() string { return "json" }

// Render writes pretty-printed JSON. SetEscapeHTML(false) keeps URLs
// human-readable (no & noise).
func (JSONReporter) Render(run *model.RunResult, w io.Writer) error {
	if run == nil {
		_, err := w.Write([]byte("{}\n"))
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(run)
}
