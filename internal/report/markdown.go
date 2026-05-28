package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/bugsyhewitt/possession/internal/model"
)

// MarkdownReporter renders a GitHub-flavored Markdown report purpose-built
// for PR comments and bug-bounty submissions. It is impact-first: a summary
// header, then one section per finding ordered by severity, each carrying a
// copy-paste reproduction (raw HTTP block + curl one-liner) inside a
// collapsible <details> block plus the owner-baseline vs. variant
// differential.
//
// Reproductions redact credential values by default (ReproOpts.ShowCreds is
// false) so the output is safe to paste into a public report. Set ShowCreds
// (via the scan --repro-creds flag) to emit live tokens for local triage.
type MarkdownReporter struct {
	// ReproOpts controls credential redaction in the per-finding repro blocks.
	ReproOpts ReproOptions
}

// Name returns "markdown".
func (MarkdownReporter) Name() string { return "markdown" }

// Render writes the full Markdown report.
func (r MarkdownReporter) Render(run *model.RunResult, w io.Writer) error {
	if run == nil {
		_, err := fmt.Fprintln(w, "_(empty run)_")
		return err
	}

	mdHeader(w, run)
	fmt.Fprintln(w)
	r.mdFindings(w, run)
	fmt.Fprintln(w)
	mdSummary(w, run)
	return nil
}

func mdHeader(w io.Writer, run *model.RunResult) {
	fmt.Fprintln(w, "# possession scan")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- **target:** `%s`\n", run.Run.BaseURL)
	if run.Run.ToolVersion != "" {
		fmt.Fprintf(w, "- **tool version:** %s\n", run.Run.ToolVersion)
	}
	fmt.Fprintf(w, "- **endpoints:** %d\n", run.Run.TotalEndpoints)
	if run.Run.Capped {
		fmt.Fprintf(w, "- **variants fired:** %d (capped from %d — increase `--max-variants` to see all)\n",
			run.Run.TotalVariants, run.Run.GeneratedTotal)
	} else {
		fmt.Fprintf(w, "- **variants fired:** %d\n", run.Run.TotalVariants)
	}
	fmt.Fprintf(w, "- **findings:** %d\n", run.Summary.TotalFindings)
	if !run.Run.Start.IsZero() && !run.Run.End.IsZero() {
		fmt.Fprintf(w, "- **runtime:** %s\n", run.Run.End.Sub(run.Run.Start).Round(time.Millisecond))
	}
}

func (r MarkdownReporter) mdFindings(w io.Writer, run *model.RunResult) {
	fmt.Fprintln(w, "## Findings")
	fmt.Fprintln(w)
	if len(run.Findings) == 0 {
		fmt.Fprintln(w, "_(none — every variant was enforced or inconclusive)_")
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
		for _, f := range group {
			r.mdFinding(w, f)
		}
	}
}

// mdFinding renders one finding section: a titled header, an at-a-glance
// metadata table, the signal trace, and a collapsible reproduction block.
func (r MarkdownReporter) mdFinding(w io.Writer, f model.Finding) {
	id := f.ID
	if len(id) > 8 {
		id = id[:8]
	}
	fmt.Fprintf(w, "### %s — `%s` on `%s`\n\n",
		strings.ToUpper(f.Severity), f.Class, f.EndpointKey)

	fmt.Fprintln(w, "| field | value |")
	fmt.Fprintln(w, "|---|---|")
	fmt.Fprintf(w, "| id | `%s` |\n", id)
	fmt.Fprintf(w, "| verdict | %s |\n", f.Verdict)
	fmt.Fprintf(w, "| confidence | %.2f |\n", f.Confidence)
	if f.ConfidenceBand != "" {
		fmt.Fprintf(w, "| band | %s |\n", f.ConfidenceBand)
	}
	fmt.Fprintf(w, "| mutation | %s |\n", f.Mutation)
	if f.Identity != "" {
		fmt.Fprintf(w, "| identity | %s |\n", f.Identity)
	}
	if len(f.ASVS) > 0 {
		fmt.Fprintf(w, "| asvs | %s |\n", strings.Join(f.ASVS, ", "))
	}
	fmt.Fprintln(w)

	if len(f.Evidence.Notes) > 0 {
		fmt.Fprintf(w, "**Signals:** %s\n\n", strings.Join(f.Evidence.Notes, "; "))
	}

	repro, ok := BuildRepro(f, r.ReproOpts)
	if !ok {
		return
	}
	fmt.Fprintf(w, "**Differential:** %s\n\n", repro.Differential)
	fmt.Fprintln(w, "<details><summary>Reproduction</summary>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "_Raw HTTP_")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "```http")
	fmt.Fprintln(w, repro.HTTP)
	fmt.Fprintln(w, "```")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "_curl_")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "```sh")
	fmt.Fprintln(w, repro.Curl)
	fmt.Fprintln(w, "```")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "</details>")
	fmt.Fprintln(w)
}

func mdSummary(w io.Writer, run *model.RunResult) {
	fmt.Fprintln(w, "## Summary")
	fmt.Fprintln(w)
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
	fmt.Fprintf(w, "- **verdicts:** %s\n", strings.Join(parts, ", "))
	fmt.Fprintf(w, "- **noisy endpoints:** %d\n", run.Summary.NoisyEndpoints)
}
