package report

import (
	"fmt"
	"html"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/bugsyhewitt/possession/internal/model"
)

// HTMLReporter renders a single self-contained, offline-interactive HTML
// document: no external CSS/JS, no network fetches, no CDN links. The whole
// report is one file an operator can open in a browser, archive, or attach to
// a ticket without losing styling.
//
// The interactive view is built from native HTML <details>/<summary> elements
// (collapsible signal traces and reproductions) so it works with JavaScript
// disabled. A tiny inline <script> adds severity filtering as progressive
// enhancement; the report is fully readable without it.
//
// Like the markdown reporter, per-finding reproductions redact credential
// values by default (ReproOpts.ShowCreds is false) so the output is safe to
// share. Set ShowCreds (via the scan --repro-creds flag) to emit live tokens
// for local triage.
type HTMLReporter struct {
	// ReproOpts controls credential redaction in the per-finding repro blocks.
	ReproOpts ReproOptions
}

// Name returns "html".
func (HTMLReporter) Name() string { return "html" }

// Render writes the full HTML document.
func (r HTMLReporter) Render(run *model.RunResult, w io.Writer) error {
	if run == nil {
		_, err := io.WriteString(w, htmlEmptyDoc)
		return err
	}

	if _, err := io.WriteString(w, htmlHead); err != nil {
		return err
	}
	htmlHeader(w, run)
	r.htmlFindings(w, run)
	htmlSummary(w, run)
	_, err := io.WriteString(w, htmlFoot)
	return err
}

const htmlEmptyDoc = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>possession scan</title></head>
<body><main><p><em>(empty run)</em></p></main></body></html>
`

// htmlHead is everything up to the opening <main>: doctype, inline styles, and
// the filter script. Kept as a raw constant so the document is deterministic
// and byte-stable across runs (important for the stability test contract the
// JSON reporter also honours).
const htmlHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>possession scan</title>
<style>
:root{--bg:#0e1116;--panel:#161b22;--fg:#e6edf3;--muted:#8b949e;--line:#30363d;
--critical:#f85149;--high:#db6d28;--medium:#d29922;--low:#3fb950;--info:#58a6ff;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:960px;margin:0 auto;padding:2rem 1.25rem 4rem}
h1{font-size:1.6rem;margin:0 0 .25rem}
h2{font-size:1.15rem;margin:2rem 0 .75rem;border-bottom:1px solid var(--line);padding-bottom:.35rem}
a{color:var(--info)}
.meta{color:var(--muted);margin:0 0 1.5rem}
.meta dl{display:grid;grid-template-columns:auto 1fr;gap:.15rem 1rem;margin:0}
.meta dt{color:var(--muted)}
.meta dd{margin:0;color:var(--fg);font-variant-numeric:tabular-nums}
.finding{background:var(--panel);border:1px solid var(--line);border-left-width:4px;
border-radius:6px;padding:.85rem 1rem;margin:0 0 1rem}
.finding[data-sev=critical]{border-left-color:var(--critical)}
.finding[data-sev=high]{border-left-color:var(--high)}
.finding[data-sev=medium]{border-left-color:var(--medium)}
.finding[data-sev=low]{border-left-color:var(--low)}
.finding[data-sev=info]{border-left-color:var(--info)}
.finding h3{margin:0 0 .5rem;font-size:1rem;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.badge{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em;
padding:.1rem .45rem;border-radius:99px;color:#0e1116}
.badge[data-sev=critical]{background:var(--critical)}
.badge[data-sev=high]{background:var(--high)}
.badge[data-sev=medium]{background:var(--medium)}
.badge[data-sev=low]{background:var(--low)}
.badge[data-sev=info]{background:var(--info)}
.ep{color:var(--muted);font-weight:400;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
table.kv{border-collapse:collapse;margin:.25rem 0 .5rem;font-size:.85rem}
table.kv td{padding:.1rem .75rem .1rem 0;vertical-align:top}
table.kv td.k{color:var(--muted)}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.signals{color:var(--muted);font-size:.85rem;margin:.25rem 0 .5rem}
.diff{font-size:.85rem;margin:.25rem 0}
details{margin:.4rem 0 0}
summary{cursor:pointer;color:var(--info);font-size:.85rem}
pre{background:#0b0e13;border:1px solid var(--line);border-radius:6px;
padding:.6rem .75rem;overflow:auto;font-size:.8rem;margin:.4rem 0}
.label{color:var(--muted);font-size:.75rem;margin:.5rem 0 .1rem;text-transform:uppercase;letter-spacing:.04em}
.controls{margin:0 0 1rem}
.controls button{background:var(--panel);color:var(--fg);border:1px solid var(--line);
border-radius:99px;padding:.25rem .7rem;margin:.15rem .25rem .15rem 0;cursor:pointer;font:inherit;font-size:.8rem}
.controls button[aria-pressed=true]{background:var(--info);color:#0e1116;border-color:var(--info)}
.empty{color:var(--muted)}
footer{color:var(--muted);font-size:.75rem;margin-top:3rem;border-top:1px solid var(--line);padding-top:1rem}
</style>
</head>
<body>
<main>
`

// htmlFoot closes main/body and carries the progressive-enhancement filter
// script. The script is inert if scripting is off; the report stays usable.
const htmlFoot = `<footer>Generated by possession — offline, self-contained report. No external resources are loaded.</footer>
<script>
(function(){
 var bar=document.querySelector('.controls'); if(!bar) return;
 var findings=Array.prototype.slice.call(document.querySelectorAll('.finding'));
 bar.addEventListener('click',function(e){
  var b=e.target.closest('button'); if(!b) return;
  var sev=b.getAttribute('data-filter');
  bar.querySelectorAll('button').forEach(function(x){x.setAttribute('aria-pressed',x===b?'true':'false');});
  findings.forEach(function(f){
   f.style.display=(sev==='all'||f.getAttribute('data-sev')===sev)?'':'none';
  });
 });
})();
</script>
</main>
</body>
</html>
`

func htmlHeader(w io.Writer, run *model.RunResult) {
	fmt.Fprintf(w, "<h1>possession scan</h1>\n")
	fmt.Fprintf(w, "<div class=\"meta\"><dl>\n")
	htmlKV(w, "target", run.Run.BaseURL)
	if run.Run.ToolVersion != "" {
		htmlKV(w, "tool version", run.Run.ToolVersion)
	}
	htmlKV(w, "endpoints", fmt.Sprintf("%d", run.Run.TotalEndpoints))
	if run.Run.Capped {
		htmlKV(w, "variants fired",
			fmt.Sprintf("%d (capped from %d — increase --max-variants to see all)",
				run.Run.TotalVariants, run.Run.GeneratedTotal))
	} else {
		htmlKV(w, "variants fired", fmt.Sprintf("%d", run.Run.TotalVariants))
	}
	htmlKV(w, "findings", fmt.Sprintf("%d", run.Summary.TotalFindings))
	if !run.Run.Start.IsZero() && !run.Run.End.IsZero() {
		htmlKV(w, "runtime", run.Run.End.Sub(run.Run.Start).Round(time.Millisecond).String())
	}
	fmt.Fprintf(w, "</dl></div>\n")
}

func htmlKV(w io.Writer, k, v string) {
	fmt.Fprintf(w, "<dt>%s</dt><dd>%s</dd>\n", html.EscapeString(k), html.EscapeString(v))
}

func (r HTMLReporter) htmlFindings(w io.Writer, run *model.RunResult) {
	fmt.Fprintf(w, "<h2>Findings</h2>\n")
	if len(run.Findings) == 0 {
		fmt.Fprintf(w, "<p class=\"empty\"><em>(none — every variant was enforced or inconclusive)</em></p>\n")
		return
	}

	// Severity filter controls (progressive enhancement; no-op without JS).
	fmt.Fprintf(w, "<div class=\"controls\">")
	fmt.Fprintf(w, "<button data-filter=\"all\" aria-pressed=\"true\">all</button>")
	for _, sev := range severityOrder {
		if countSeverity(run.Findings, sev) == 0 {
			continue
		}
		fmt.Fprintf(w, "<button data-filter=\"%s\">%s (%d)</button>",
			sev, html.EscapeString(sev), countSeverity(run.Findings, sev))
	}
	fmt.Fprintf(w, "</div>\n")

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
			r.htmlFinding(w, f)
		}
	}
}

func countSeverity(findings []model.Finding, sev string) int {
	n := 0
	for _, f := range findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

func (r HTMLReporter) htmlFinding(w io.Writer, f model.Finding) {
	id := f.ID
	if len(id) > 8 {
		id = id[:8]
	}
	sev := html.EscapeString(f.Severity)
	fmt.Fprintf(w, "<div class=\"finding\" data-sev=\"%s\">\n", sev)
	fmt.Fprintf(w, "<h3><span class=\"badge\" data-sev=\"%s\">%s</span> <code>%s</code> <span class=\"ep\">%s</span></h3>\n",
		sev, sev, html.EscapeString(f.Class), html.EscapeString(f.EndpointKey))

	fmt.Fprintf(w, "<table class=\"kv\">\n")
	htmlRow(w, "id", id)
	htmlRow(w, "verdict", f.Verdict)
	htmlRow(w, "confidence", fmt.Sprintf("%.2f", f.Confidence))
	if f.ConfidenceBand != "" {
		htmlRow(w, "band", f.ConfidenceBand)
	}
	htmlRow(w, "mutation", f.Mutation)
	if f.Identity != "" {
		htmlRow(w, "identity", f.Identity)
	}
	if len(f.ASVS) > 0 {
		htmlRow(w, "asvs", strings.Join(f.ASVS, ", "))
	}
	fmt.Fprintf(w, "</table>\n")

	if len(f.Evidence.Notes) > 0 {
		fmt.Fprintf(w, "<div class=\"signals\"><strong>Signals:</strong> %s</div>\n",
			html.EscapeString(strings.Join(f.Evidence.Notes, "; ")))
	}

	repro, ok := BuildRepro(f, r.ReproOpts)
	if !ok {
		fmt.Fprintf(w, "</div>\n")
		return
	}
	fmt.Fprintf(w, "<div class=\"diff\"><strong>Differential:</strong> %s</div>\n",
		html.EscapeString(repro.Differential))
	fmt.Fprintf(w, "<details><summary>Reproduction</summary>\n")
	fmt.Fprintf(w, "<div class=\"label\">Raw HTTP</div>\n")
	fmt.Fprintf(w, "<pre>%s</pre>\n", html.EscapeString(repro.HTTP))
	fmt.Fprintf(w, "<div class=\"label\">curl</div>\n")
	fmt.Fprintf(w, "<pre>%s</pre>\n", html.EscapeString(repro.Curl))
	fmt.Fprintf(w, "</details>\n")
	fmt.Fprintf(w, "</div>\n")
}

func htmlRow(w io.Writer, k, v string) {
	fmt.Fprintf(w, "<tr><td class=\"k\">%s</td><td>%s</td></tr>\n",
		html.EscapeString(k), html.EscapeString(v))
}

func htmlSummary(w io.Writer, run *model.RunResult) {
	fmt.Fprintf(w, "<h2>Summary</h2>\n")
	verdicts := run.Summary.Verdicts
	keys := make([]string, 0, len(verdicts))
	for k := range verdicts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", html.EscapeString(k), verdicts[k]))
	}
	fmt.Fprintf(w, "<table class=\"kv\">\n")
	htmlRow(w, "verdicts", strings.Join(parts, ", "))
	htmlRow(w, "noisy endpoints", fmt.Sprintf("%d", run.Summary.NoisyEndpoints))
	fmt.Fprintf(w, "</table>\n")
}
