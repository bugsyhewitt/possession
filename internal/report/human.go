package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bugsyhewitt/possession/internal/model"
)

// HumanReporter renders a plain-ASCII report suitable for terminals and
// log piping. It is the default --report value because it's the form
// most operators read directly. Sections:
//
//  1. Header (target, totals, runtime)
//  2. Findings grouped by severity
//  3. Per-endpoint auth-dependency matrix (which identities × which
//     dropped components changed access)
//  4. Endpoint notes (typed)
//  5. Summary footer
//
// All tables use text/tabwriter for ASCII alignment. No color by
// default — terminals piped to less/grep do not benefit from it.
type HumanReporter struct{}

// Name returns "human".
func (HumanReporter) Name() string { return "human" }

// Render writes the full ASCII report.
func (HumanReporter) Render(run *model.RunResult, w io.Writer) error {
	if run == nil {
		_, err := fmt.Fprintln(w, "(empty run)")
		return err
	}

	renderHeader(w, run)
	fmt.Fprintln(w)
	renderFindings(w, run)
	fmt.Fprintln(w)
	renderAuthDependencyMatrix(w, run)
	fmt.Fprintln(w)
	renderEndpointNotes(w, run)
	fmt.Fprintln(w)
	renderSummary(w, run)
	return nil
}

func renderHeader(w io.Writer, run *model.RunResult) {
	fmt.Fprintln(w, "═══ possession scan ═══════════════════════════════════════════")
	fmt.Fprintf(w, "target:          %s\n", run.Run.BaseURL)
	if run.Run.ToolVersion != "" {
		fmt.Fprintf(w, "tool version:    %s\n", run.Run.ToolVersion)
	}
	fmt.Fprintf(w, "endpoints:       %d\n", run.Run.TotalEndpoints)
	fmt.Fprintf(w, "variants fired:  %d", run.Run.TotalVariants)
	if run.Run.Capped {
		fmt.Fprintf(w, " (capped from %d — increase --max-variants to see all)", run.Run.GeneratedTotal)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "findings:        %d\n", run.Summary.TotalFindings)
	if !run.Run.Start.IsZero() && !run.Run.End.IsZero() {
		fmt.Fprintf(w, "runtime:         %s\n", run.Run.End.Sub(run.Run.Start).Round(time.Millisecond))
	}
}

// severityOrder is critical → info; used for grouped output.
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

func renderFindings(w io.Writer, run *model.RunResult) {
	fmt.Fprintln(w, "─── findings ──────────────────────────────────────────────────")
	if len(run.Findings) == 0 {
		fmt.Fprintln(w, "  (none — every variant was enforced or inconclusive)")
		return
	}
	bySev := make(map[string][]model.Finding, len(severityOrder))
	for _, f := range run.Findings {
		bySev[f.Severity] = append(bySev[f.Severity], f)
	}
	for _, sev := range severityOrder {
		group := bySev[sev]
		if len(group) == 0 {
			continue
		}
		sort.SliceStable(group, func(i, j int) bool {
			if group[i].Confidence != group[j].Confidence {
				return group[i].Confidence > group[j].Confidence
			}
			return group[i].EndpointKey < group[j].EndpointKey
		})
		fmt.Fprintf(w, "\n  %s (%d):\n", strings.ToUpper(sev), len(group))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "    CLASS\tENDPOINT\tVERDICT\tCONF\tMUTATION\tASVS")
		for _, f := range group {
			asvs := strings.Join(f.ASVS, ",")
			fmt.Fprintf(tw, "    %s\t%s\t%s\t%.2f\t%s\t%s\n",
				f.Class, f.EndpointKey, f.Verdict, f.Confidence, f.Mutation, asvs)
		}
		tw.Flush()
		// One-line signal trace per finding.
		for _, f := range group {
			if len(f.Evidence.Notes) == 0 {
				continue
			}
			fmt.Fprintf(w, "      ↳ %s: %s\n", f.ID[:8], strings.Join(f.Evidence.Notes, "; "))
		}
	}
}

func renderAuthDependencyMatrix(w io.Writer, run *model.RunResult) {
	// Build matrix: for each endpoint, the set of (mutation, identity) →
	// verdict. Restrict to auth-dependency-class findings + the variants
	// they came from. This is "which auth components actually matter".
	type cell struct {
		mutation string
		identity string
		verdict  string
	}
	byEndpoint := map[string][]cell{}
	for _, f := range run.Findings {
		if f.Class != "auth-dependency" {
			continue
		}
		byEndpoint[f.EndpointKey] = append(byEndpoint[f.EndpointKey],
			cell{mutation: f.Mutation, identity: f.Identity, verdict: f.Verdict})
	}
	if len(byEndpoint) == 0 {
		fmt.Fprintln(w, "─── auth-dependency matrix ─────────────────────────────────────")
		fmt.Fprintln(w, "  (no auth-dependency findings; each auth component was either")
		fmt.Fprintln(w, "   required by the server or not tested in this run)")
		return
	}
	fmt.Fprintln(w, "─── auth-dependency matrix ─────────────────────────────────────")
	fmt.Fprintln(w, "  Which auth components actually gate access? (one row per finding)")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  ENDPOINT\tMUTATION\tIDENTITY\tVERDICT")
	keys := make([]string, 0, len(byEndpoint))
	for k := range byEndpoint {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cells := byEndpoint[k]
		sort.SliceStable(cells, func(i, j int) bool {
			if cells[i].mutation != cells[j].mutation {
				return cells[i].mutation < cells[j].mutation
			}
			return cells[i].identity < cells[j].identity
		})
		for _, c := range cells {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", k, c.mutation, c.identity, c.verdict)
		}
	}
	tw.Flush()
}

func renderEndpointNotes(w io.Writer, run *model.RunResult) {
	hasNotes := false
	for _, ep := range run.Endpoints {
		if len(ep.Notes) > 0 {
			hasNotes = true
			break
		}
	}
	if !hasNotes {
		return
	}
	fmt.Fprintln(w, "─── endpoint notes ─────────────────────────────────────────────")
	for _, ep := range run.Endpoints {
		if len(ep.Notes) == 0 {
			continue
		}
		fmt.Fprintf(w, "  %s:\n", ep.Key)
		for _, n := range ep.Notes {
			msg := n.Message
			if msg == "" {
				msg = n.Code
			}
			fmt.Fprintf(w, "    • [%s] %s\n", n.Code, msg)
		}
	}
}

func renderSummary(w io.Writer, run *model.RunResult) {
	fmt.Fprintln(w, "─── summary ────────────────────────────────────────────────────")
	verdicts := run.Summary.Verdicts
	keys := make([]string, 0, len(verdicts))
	for k := range verdicts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, verdicts[k]))
	}
	fmt.Fprintf(w, "  verdicts:        %s\n", strings.Join(parts, ", "))
	fmt.Fprintf(w, "  noisy endpoints: %d\n", run.Summary.NoisyEndpoints)
	if !run.Run.Start.IsZero() && !run.Run.End.IsZero() {
		fmt.Fprintf(w, "  runtime:         %s\n", run.Run.End.Sub(run.Run.Start).Round(time.Millisecond))
	}
}
