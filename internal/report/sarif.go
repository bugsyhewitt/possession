package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
	"github.com/owenrumney/go-sarif/v3/pkg/report"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

// SARIFReporter emits SARIF 2.1.0 via owenrumney/go-sarif/v3. The
// output is suitable for GitHub Code Scanning's `--report sarif --out
// results.sarif` upload path.
//
// One rule per finding class (idor, authn-bypass, privesc, auth-
// dependency); one result per finding. Severity is mapped to SARIF
// `level`: critical/high → error, medium → warning, low/info → note.
// ASVS controls are surfaced both in the rule's helpUri and in its
// property bag.
type SARIFReporter struct{}

// Name returns "sarif".
func (SARIFReporter) Name() string { return "sarif" }

const (
	informationURI  = "https://github.com/bugsyhewitt/possession"
	asvsHelpURIBase = "https://owasp.org/www-project-application-security-verification-standard/"
)

// classDescriptions are short + full descriptions surfaced in the SARIF
// rule. Kept here so reporters that don't render them (human/json)
// don't drag the strings around.
var classDescriptions = map[string][2]string{
	"idor": {
		"Insecure direct object reference",
		"A request issued under a peer identity returned the resource owner's data — the server failed to enforce per-object authorization (IDOR).",
	},
	"authn-bypass": {
		"Authentication bypass",
		"A request stripped of credentials (or with an invalid/forged token) was answered as if authenticated — the server failed to require valid authentication.",
	},
	"privesc": {
		"Privilege escalation",
		"A lower-rank identity (or a token with tampered role/scope claims) gained access to a higher-rank-only endpoint — the server failed to enforce role-based access control.",
	},
	"auth-dependency": {
		"Auth-component dependency",
		"Dropping one auth component (e.g. a single cookie or the CSRF header) did not change access, meaning the dropped component is not actually being enforced.",
	},
}

// classOrder fixes the order rules are added so SARIF output is stable
// across runs even when findings vary.
var classOrder = []string{"authn-bypass", "idor", "privesc", "auth-dependency"}

// severityToLevel maps possession severities to SARIF levels.
func severityToLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// Render assembles a SARIF 2.1.0 document and writes it to w.
func (SARIFReporter) Render(run *model.RunResult, w io.Writer) error {
	if run == nil {
		_, err := w.Write([]byte("{}\n"))
		return err
	}

	rpt := report.NewV210Report()
	srun := sarif.NewRunWithInformationURI("possession", informationURI)

	// Tool version — surface what was passed in RunMeta.ToolVersion.
	if srun.Tool != nil && srun.Tool.Driver != nil && run.Run.ToolVersion != "" {
		v := run.Run.ToolVersion
		srun.Tool.Driver.Version = &v
	}

	// Pre-register one rule per class so even classes with zero findings
	// in this run are documented (helpful for CI suppression rules).
	classesUsed := make(map[string]bool, len(run.Findings))
	for _, f := range run.Findings {
		classesUsed[f.Class] = true
	}
	for _, class := range classOrder {
		if !classesUsed[class] {
			continue
		}
		short, long := classDescriptions[class][0], classDescriptions[class][1]
		asvsIDs := asvsForClass(class)
		helpURI := asvsHelpURIBase
		pb := sarif.NewPropertyBag()
		pb.Add("asvs_v5", strings.Join(asvsIDs, ","))
		pb.Add("asvs_chapter", "V8 (Authorization)")
		srun.AddRule(class).
			WithDescription(short).
			WithFullDescription(sarif.NewMultiformatMessageString().WithText(long)).
			WithHelpURI(helpURI).
			WithProperties(pb)
	}

	// Stable result order: by (severity rank, endpoint key, finding id).
	findings := append([]model.Finding(nil), run.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if findings[i].EndpointKey != findings[j].EndpointKey {
			return findings[i].EndpointKey < findings[j].EndpointKey
		}
		return findings[i].ID < findings[j].ID
	})

	for _, f := range findings {
		level := severityToLevel(f.Severity)
		msgText := fmt.Sprintf("%s on %s — verdict=%s, mutation=%s, confidence=%.2f",
			f.Class, f.EndpointKey, f.Verdict, f.Mutation, f.Confidence)

		method, pathTmpl := splitEndpointKey(f.EndpointKey)
		uri := pathTmpl
		if uri == "" {
			uri = f.EndpointKey
		}

		// Property bag with possession-specific fields.
		pb := sarif.NewPropertyBag()
		pb.Add("confidence", f.Confidence)
		pb.Add("verdict", f.Verdict)
		pb.Add("similarity", f.Evidence.SimilarityScore)
		pb.Add("mutation", f.Mutation)
		if f.Identity != "" {
			pb.Add("identity", f.Identity)
		}
		pb.Add("asvs_v5", strings.Join(f.ASVS, ","))
		if method != "" {
			pb.Add("http_method", method)
		}

		result := srun.CreateResultForRule(f.Class).
			WithLevel(level).
			WithMessage(sarif.NewTextMessage(msgText)).
			WithProperties(pb).
			AddLocation(
				sarif.NewLocationWithPhysicalLocation(
					sarif.NewPhysicalLocation().
						WithArtifactLocation(sarif.NewSimpleArtifactLocation(uri)),
				),
			)

		// partialFingerprints uses Finding.ID for code-scanning dedupe.
		result.PartialFingerprints = map[string]string{
			"possession/finding/v1": f.ID,
		}
	}

	rpt.AddRun(srun)
	return rpt.PrettyWrite(w)
}

// asvsForClass returns ASVS v5.0 control IDs for a finding class.
// Mirrors detect.ASVSByClass but we avoid importing detect from the
// report package to keep dependencies flat.
//
// Gate F: V9 (Self-Contained Tokens) control IDs are NOT included.
// Without confirmed exact V9 IDs from the ASVS v5.0.0 spec, the brief
// requires us to map V8 only and document it.
func asvsForClass(class string) []string {
	switch class {
	case "authn-bypass":
		return []string{"v5.0.0-8.3.1"}
	case "idor":
		return []string{"v5.0.0-8.2.2"}
	case "idor-cross-tenant":
		return []string{"v5.0.0-8.4.1", "v5.0.0-8.2.2"}
	case "privesc":
		return []string{"v5.0.0-8.2.1"}
	case "auth-dependency":
		return []string{"v5.0.0-8.3.1"}
	default:
		return nil
	}
}

func severityRank(sev string) int {
	switch sev {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	default:
		return 5
	}
}

// splitEndpointKey splits "METHOD host/path" into method and path.
// Used for the SARIF logical location.
func splitEndpointKey(key string) (method, pathTmpl string) {
	if i := strings.Index(key, " "); i > 0 {
		method = key[:i]
		rest := key[i+1:]
		if j := strings.Index(rest, "/"); j >= 0 {
			pathTmpl = rest[j:]
		} else {
			pathTmpl = rest
		}
	}
	return
}
