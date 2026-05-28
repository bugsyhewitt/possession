package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bugsyhewitt/possession/internal/config"
	"github.com/bugsyhewitt/possession/internal/detect"
	"github.com/bugsyhewitt/possession/internal/model"
	"github.com/bugsyhewitt/possession/internal/mutate"
	"github.com/bugsyhewitt/possession/internal/normalize"
	"github.com/bugsyhewitt/possession/internal/parse"
	"github.com/bugsyhewitt/possession/internal/replay"
	"github.com/bugsyhewitt/possession/internal/report"
	"github.com/bugsyhewitt/possession/internal/suppress"
)

var (
	scanMatrix          string
	scanFormat          string
	scanRate            float64
	scanConcurrency     int
	scanMaxVariants     int
	scanMaxBody         string
	scanNoLimit         bool
	scanInsecure        bool
	scanOut             string
	scanDryRun          bool
	scanBaselineSamples int
	scanMinConfidence   float64
	scanReport          string
	scanExitZero        bool
	scanJWTWordlist     string // path to newline-delimited HMAC secret wordlist
	scanEvaluator       string // evaluator to use: comparative | assertion | both
	scanAllowlist       string // path to possession.allowlist suppression file
	scanUpdateAllowlist bool   // merge current findings into the allowlist file
	scanEnumerate       int    // --enumerate N: sequential ID enumeration range (0 = off)
	scanJWTAttack       bool   // --jwt-attack: forge alg:none + blank-secret tokens (off by default)
)

// scanCmd is the end-to-end scan command. Packets 1-3 contribute:
//   - P1 parse/normalize/scope/dedup
//   - P2 mutators + variant plan + replay engine + refresh hooks
//   - P3 owner attribution + calibrated baseline + ComparativeEvaluator +
//     findings + extended JSON output schema
var scanCmd = &cobra.Command{
	Use:           "scan <input>",
	Short:         "Run an authz scan against a target.",
	Args:          cobra.MaximumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanMatrix, "matrix", "", "role-matrix YAML (required)")
	scanCmd.Flags().StringVar(&scanFormat, "format", "auto", "input format: har | curl | openapi | auto")
	scanCmd.Flags().Float64Var(&scanRate, "rate", 0, "per-host requests per second (default from matrix or 10)")
	scanCmd.Flags().IntVar(&scanConcurrency, "concurrency", 0, "max in-flight requests (default from matrix or 5)")
	scanCmd.Flags().IntVar(&scanMaxVariants, "max-variants", 0, "cap on total variants generated (default 10000)")
	scanCmd.Flags().StringVar(&scanMaxBody, "max-body", "5MB", "per-response body cap (e.g. 5MB, 10KB)")
	scanCmd.Flags().BoolVar(&scanNoLimit, "no-limit", false, "disable per-host rate limiter (DANGEROUS)")
	scanCmd.Flags().BoolVar(&scanInsecure, "insecure", false, "disable TLS verification (DANGEROUS, lab-only)")
	scanCmd.Flags().StringVar(&scanOut, "out", "", "write JSON results to file (default stdout)")
	scanCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, "print variant plan; fire no requests")
	scanCmd.Flags().IntVar(&scanBaselineSamples, "baseline-samples", detect.DefaultBaselineSamples,
		"owner self-replay samples per endpoint for calibration (clamped 1..10)")
	scanCmd.Flags().Float64Var(&scanMinConfidence, "min-confidence", 0.0,
		"omit findings with confidence below this from the findings array (summary still counts them)")
	scanCmd.Flags().StringVar(&scanReport, "report", "human",
		"output format: human | json | sarif")
	scanCmd.Flags().BoolVar(&scanExitZero, "exit-zero", false,
		"exit 0 even when findings are present (useful in CI pipelines that gate elsewhere)")
	scanCmd.Flags().StringVar(&scanJWTWordlist, "jwt-wordlist", "",
		"path to newline-delimited wordlist for jwt-hmac-crack (default: built-in list)")
	scanCmd.Flags().StringVar(&scanEvaluator, "evaluator", "comparative",
		"evaluator to use: comparative | assertion | both (default: comparative)")
	scanCmd.Flags().StringVar(&scanAllowlist, "allowlist", "",
		"path to a possession.allowlist YAML file; suppresses known findings from output")
	scanCmd.Flags().BoolVar(&scanUpdateAllowlist, "update-allowlist", false,
		"merge all findings from this run into --allowlist (creates the file if absent; requires --allowlist)")
	scanCmd.Flags().IntVar(&scanEnumerate, "enumerate", 0,
		"sequential ID enumeration range N: probe captured±N neighbors for numeric path segments (0 = disabled; rate-sensitive, use with --rate)")
	scanCmd.Flags().BoolVar(&scanJWTAttack, "jwt-attack", false,
		"forge token-level auth-bypass JWTs for each captured Bearer token: alg:none + blank-secret (off by default; noisier than identity swap)")
}

func resetScanFlags() {
	scanMatrix = ""
	scanFormat = "auto"
	scanRate = 0
	scanConcurrency = 0
	scanMaxVariants = 0
	scanMaxBody = "5MB"
	scanNoLimit = false
	scanInsecure = false
	scanOut = ""
	scanDryRun = false
	scanBaselineSamples = detect.DefaultBaselineSamples
	scanMinConfidence = 0.0
	scanReport = "human"
	scanExitZero = false
	scanJWTWordlist = ""
	scanEvaluator = "comparative"
	scanAllowlist = ""
	scanUpdateAllowlist = false
	scanEnumerate = 0
	scanJWTAttack = false
}

func runScan(cmd *cobra.Command, args []string) error {
	if scanMatrix == "" {
		return fmt.Errorf("scan: --matrix is required")
	}
	if len(args) != 1 {
		return fmt.Errorf("scan: exactly one input file is required")
	}
	if scanUpdateAllowlist && scanAllowlist == "" {
		return fmt.Errorf("scan: --update-allowlist requires --allowlist <path>")
	}
	input := args[0]

	matrix, err := config.LoadFile(scanMatrix)
	if err != nil {
		return err
	}

	// Load suppression allowlist (if --allowlist provided). Missing file is
	// not an error — it just means no suppressions.
	var allowlist *suppress.Allowlist
	if scanAllowlist != "" {
		allowlist, err = suppress.LoadFile(scanAllowlist)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
	}

	if scanRate == 0 {
		scanRate = matrix.Settings.RatePerHost
		if scanRate == 0 {
			scanRate = 10
		}
	}
	if scanConcurrency == 0 {
		scanConcurrency = matrix.Settings.Concurrency
		if scanConcurrency == 0 {
			scanConcurrency = 5
		}
	}
	if scanMaxVariants == 0 {
		scanMaxVariants = replay.DefaultMaxVariants
	}
	maxBodyBytes, err := parseSize(scanMaxBody)
	if err != nil {
		return fmt.Errorf("scan: --max-body: %w", err)
	}
	baselineSamples := detect.ClampBaselineSamples(scanBaselineSamples)

	stderr := cmd.ErrOrStderr()
	if scanNoLimit {
		fmt.Fprintln(stderr, "!!! --no-limit: per-host rate limiter DISABLED. You may overwhelm the target.")
		fmt.Fprintln(stderr, "!!! Only use this against systems you own and have permission to scan.")
	}
	if scanInsecure {
		fmt.Fprintln(stderr, "!!! --insecure: TLS verification DISABLED. MITM attacks possible.")
	}

	format, err := detectFormat(input, scanFormat)
	if err != nil {
		return err
	}
	f, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("scan: open %s: %w", input, err)
	}
	defer f.Close()

	var requests []*model.CapturedRequest
	switch format {
	case "har":
		requests, err = parse.HAR(f)
	case "curl":
		var req *model.CapturedRequest
		req, err = parse.Curl(f)
		if req != nil {
			requests = []*model.CapturedRequest{req}
		}
	case "openapi":
		requests, err = parse.OpenAPI(f)
	}
	if err != nil {
		return err
	}

	normalize.Apply(requests)
	requests = applyScope(requests, matrix.Scope)
	endpoints := normalize.Dedup(requests)

	// Owner attribution (P3 / D17). Each endpoint gets an OwnerIdentity
	// derived from its representative sample's auth components.
	attributionWarnings := attributeEndpoints(endpoints, matrix)

	reg, err := buildRegistry(scanJWTWordlist, scanEnumerate, scanJWTAttack)
	if err != nil {
		return err
	}
	plan := replay.Generate(endpoints, matrix, reg, scanMaxVariants)
	if plan.Capped {
		fmt.Fprintf(stderr,
			"!!! variant cap hit: generated %d but capped at %d. Increase --max-variants to see them all.\n",
			plan.TotalBefore, scanMaxVariants)
	}

	if scanDryRun {
		return writeDryRun(cmd.OutOrStdout(), plan, endpoints, baselineSamples)
	}

	// Build the baseline plan: N owner self-replay variants per endpoint.
	baselinePlan := buildBaselinePlan(endpoints, baselineSamples)

	rs := matrix.Settings
	rs.RatePerHost = scanRate
	rs.Concurrency = scanConcurrency
	rs.MaxBody = maxBodyBytes
	rs.MaxVariants = scanMaxVariants
	rs.NoLimit = scanNoLimit
	rs.Insecure = scanInsecure

	engine := replay.New(rs, "possession/"+buildVersion, stderr)

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	start := time.Now()
	engine.PrepareRefresh(ctx, matrix)
	engine.PrepareFlows(ctx, matrix)
	baselineResponses := engine.Run(ctx, baselinePlan)
	responses := engine.Run(ctx, plan)
	end := time.Now()

	// Group baseline responses by endpoint key.
	baselineByEndpoint := make(map[string][]*model.Response)
	for i, v := range baselinePlan.Variants {
		key := endpointKeyOfVariant(&v)
		r := baselineResponses[i]
		baselineByEndpoint[key] = append(baselineByEndpoint[key], &r)
	}

	// Detection — per endpoint.
	ev, err := buildEvaluator(scanEvaluator, matrix)
	if err != nil {
		return err
	}
	allFindings := []model.Finding{}
	verdictCounts := map[string]int{
		detect.VerdictBypass:       0,
		detect.VerdictSuspected:    0,
		detect.VerdictEnforced:     0,
		detect.VerdictInconclusive: 0,
	}
	noisyCount := 0
	endpointReports := make([]endpointReport, 0, len(endpoints))

	for _, ep := range endpoints {
		key := endpointKeyOf(ep)
		baselineSamples := baselineByEndpoint[key]
		cal := detect.Calibrate(baselineSamples)
		if cal.Noisy {
			noisyCount++
		}

		// Collect variant responses for this endpoint.
		var vrs []detect.VariantResponse
		for i, v := range plan.Variants {
			if endpointKeyOfVariant(&v) != key {
				continue
			}
			r := responses[i]
			vrs = append(vrs, detect.VariantResponse{
				Variant:  &plan.Variants[i],
				Response: &r,
			})
		}

		ctxEval := detect.EvalContext{
			Endpoint:         ep,
			Owner:            ep.OwnerIdentity,
			BaselineSamples:  baselineSamples,
			Calibration:      cal,
			VariantResponses: vrs,
			Matrix:           matrix,
		}
		res := ev.Evaluate(ctxEval)
		for _, vv := range res.Verdicts {
			verdictCounts[vv.Verdict]++
		}
		// Append findings, applying --min-confidence filter (but counts already
		// in verdictCounts).
		filteredFindings := []model.Finding{}
		omittedByMinConf := 0
		for _, f := range res.Findings {
			if f.Confidence < scanMinConfidence {
				omittedByMinConf++
				continue
			}
			filteredFindings = append(filteredFindings, f)
		}
		allFindings = append(allFindings, filteredFindings...)

		// Per-endpoint notes — typed enum per D29. Start with calibration
		// notes, then layer on refresh failures and min-confidence omissions
		// observed at this scope.
		notes := append([]detect.EndpointNote{}, cal.Notes...)
		refreshFailedFor := map[string]struct{}{}
		for _, vr := range vrs {
			if vr.Response != nil && vr.Response.Inconclusive && vr.Variant != nil && vr.Variant.Identity != nil {
				refreshFailedFor[vr.Variant.Identity.Name] = struct{}{}
			}
		}
		names := make([]string, 0, len(refreshFailedFor))
		for n := range refreshFailedFor {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			notes = append(notes, detect.NewNote(detect.NoteRefreshFailed, map[string]string{"identity": n}))
		}
		if omittedByMinConf > 0 {
			notes = append(notes, detect.NewNote(detect.NoteMinConfidence, map[string]string{"omitted": strconv.Itoa(omittedByMinConf)}))
		}

		owner := ""
		ownerAttr := ep.OwnerAttribution
		if ep.OwnerIdentity != nil {
			owner = ep.OwnerIdentity.Name
		}
		endpointReports = append(endpointReports, endpointReport{
			Key:               key,
			Method:            ep.Method,
			Host:              ep.Host,
			PathTemplate:      ep.PathTemplate,
			Owner:             owner,
			OwnerAttribution:  ownerAttr,
			BaselineSamples:   cal.Samples,
			BaselineStatus:    cal.BaselineStatus,
			Stability:         cal.Stability,
			EffThreshold:      cal.EffThreshold,
			Noisy:             cal.Noisy,
			CalibrationSkipped: cal.Skipped,
			BaselineFailed:    cal.BaselineFailed,
			Notes:             notes,
		})
	}

	// Cluster enumerate-id findings: collapse N per-probe-ID findings for
	// the same endpoint into one summary idor finding with an evidence list.
	// This keeps the finding count readable when --enumerate produces a large
	// sweep (20+ probes per endpoint).
	allFindings = clusterEnumerateFindings(allFindings)

	// Allowlist suppression: remove known findings before summary + reporting.
	// If --update-allowlist is set, merge ALL findings (pre-suppression) into
	// the allowlist file first, then apply suppression. This way the file
	// always reflects the full set, and subsequent runs suppress everything
	// in it.
	suppressedCount := 0
	if allowlist != nil {
		if scanUpdateAllowlist {
			merged := suppress.Merge(allowlist, suppress.FromFindings(allFindings, "", ""))
			if werr := suppress.WriteFile(scanAllowlist, merged); werr != nil {
				fmt.Fprintf(stderr, "warning: could not update allowlist %s: %v\n", scanAllowlist, werr)
			} else {
				fmt.Fprintf(stderr, "allowlist updated: %s (%d entries)\n", scanAllowlist, len(merged.Entries))
				allowlist = merged
			}
		}
		allFindings, suppressedCount = suppress.Apply(allFindings, allowlist)
		if suppressedCount > 0 {
			fmt.Fprintf(stderr, "%d finding(s) suppressed by allowlist %s\n", suppressedCount, scanAllowlist)
		}
	}

	// Build summary.
	byClass := map[string]int{}
	bySeverity := map[string]int{}
	for _, f := range allFindings {
		byClass[f.Class]++
		bySeverity[f.Severity]++
	}

	// Map endpoint_key → primary baseline variant id (first baseline for that key).
	baselineMap := map[string]string{}
	for i, v := range baselinePlan.Variants {
		key := endpointKeyOfVariant(&v)
		if _, ok := baselineMap[key]; !ok {
			baselineMap[key] = baselinePlan.Variants[i].ID
		}
	}

	// D30: Mutation.Class is set by each mutator at variant generation;
	// no re-derivation here. Variants from baseline-self or future
	// custom mutators that don't set Class will simply emit empty class
	// in JSON — which is correct (they don't produce findings).

	runResult := buildRunResult(matrix, endpoints, plan, responses, start, end, rs, buildResultExtras{
		Baselines:       baselineMap,
		BaselineSamples: baselineSamples,
		EndpointReports: endpointReports,
		Findings:        allFindings,
		Summary: summaryView{
			Verdicts:       verdictCounts,
			NoisyEndpoints: noisyCount,
			ByClass:        byClass,
			BySeverity:     bySeverity,
			TotalFindings:  len(allFindings),
		},
		AttributionWarnings: attributionWarnings,
	})

	reporter, err := report.New(scanReport)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	w := cmd.OutOrStdout()
	if scanOut != "" {
		fh, err := os.Create(scanOut)
		if err != nil {
			return fmt.Errorf("scan: create %s: %w", scanOut, err)
		}
		defer fh.Close()
		w = fh
	}
	if err := reporter.Render(runResult, w); err != nil {
		return fmt.Errorf("scan: render %s: %w", reporter.Name(), err)
	}

	// Exit code 3 when findings present and --exit-zero not set. Cobra
	// wraps RunE errors as exit 1, so we use a typed exitError that
	// main.go inspects to produce the correct code.
	if len(allFindings) > 0 && !scanExitZero {
		return &ExitError{Code: 3, Msg: fmt.Sprintf("%d finding(s) reported", len(allFindings))}
	}
	return nil
}

// ExitError signals a non-zero exit code distinct from cobra's default 1.
// main.go checks for this type and propagates the embedded code.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

// attributeEndpoints fills in OwnerIdentity and OwnerAttribution on each
// endpoint and returns any ambiguity warnings to surface at run level.
func attributeEndpoints(endpoints []*model.Endpoint, matrix *model.RoleMatrix) []string {
	var warnings []string
	for _, ep := range endpoints {
		if ep == nil || len(ep.Samples) == 0 {
			continue
		}
		sample := ep.Samples[0]
		for _, s := range ep.Samples[1:] {
			if s != nil && (sample == nil || s.ID < sample.ID) {
				sample = s
			}
		}
		owner, attr, warns := detect.AttributeOwner(sample, matrix)
		ep.OwnerIdentity = owner
		ep.OwnerAttribution = attr
		for _, w := range warns {
			warnings = append(warnings, endpointKeyOf(ep)+": "+w)
		}
	}
	return warnings
}

// buildBaselinePlan creates N owner-baseline replay variants per endpoint.
// The baseline variant is a copy of the captured request with the owner's
// credentials applied via the same mechanism the replay engine uses for
// per-variant identity work — but since the captured request already
// carries those creds (it IS the owner's request), we just clone it.
func buildBaselinePlan(endpoints []*model.Endpoint, samples int) replay.Plan {
	plan := replay.Plan{}
	for _, ep := range endpoints {
		if ep == nil || len(ep.Samples) == 0 || ep.OwnerIdentity == nil {
			continue
		}
		// Pick representative sample (smallest ID).
		best := ep.Samples[0]
		for _, s := range ep.Samples[1:] {
			if s != nil && (best == nil || s.ID < best.ID) {
				best = s
			}
		}
		if best == nil {
			continue
		}
		ownerCopy := *ep.OwnerIdentity
		for i := 0; i < samples; i++ {
			clone := mutate.CloneRequest(best)
			v := model.Variant{
				ID:       fmt.Sprintf("baseline-%s-%d", ep.OwnerIdentity.Name, i) + "-" + best.ID,
				Base:     clone,
				Identity: &ownerCopy,
				Mutation: model.Mutation{
					Type:        "baseline-self",
					Description: "owner self-replay baseline",
					Detail:      map[string]string{"sample": strconv.Itoa(i)},
					Class:       "", // baselines never produce findings
				},
			}
			plan.Variants = append(plan.Variants, v)
		}
	}
	plan.TotalBefore = len(plan.Variants)
	return plan
}

func endpointKeyOf(ep *model.Endpoint) string {
	if ep == nil {
		return ""
	}
	return ep.Method + " " + ep.Host + ep.PathTemplate
}

func endpointKeyOfVariant(v *model.Variant) string {
	if v == nil || v.Base == nil || v.Base.URL == nil {
		return ""
	}
	host := v.Base.URL.Host
	tmpl := v.Base.PathTemplate
	if tmpl == "" {
		tmpl = v.Base.URL.Path
	}
	return v.Base.Method + " " + host + tmpl
}

// --- internal aggregation shapes ---
//
// These local types live alongside the model.RunResult types and are
// used to collect per-endpoint stats before the reporter render. They
// shadow the model side so the scan loop doesn't have to know about the
// model package's JSON tags or the typed EndpointNote mirror.

type endpointReport struct {
	Key                string                `json:"key"`
	Method             string                `json:"method"`
	Host               string                `json:"host"`
	PathTemplate       string                `json:"path_template"`
	Owner              string                `json:"owner,omitempty"`
	OwnerAttribution   string                `json:"owner_attribution,omitempty"`
	BaselineSamples    int                   `json:"baseline_samples"`
	BaselineStatus     int                   `json:"baseline_status"`
	Stability          float64               `json:"stability"`
	EffThreshold       float64               `json:"eff_threshold"`
	Noisy              bool                  `json:"noisy"`
	CalibrationSkipped bool                  `json:"calibration_skipped"`
	BaselineFailed     bool                  `json:"baseline_failed"`
	Notes              []detect.EndpointNote `json:"notes,omitempty"`
}

type summaryView struct {
	Verdicts       map[string]int
	NoisyEndpoints int
	ByClass        map[string]int
	BySeverity     map[string]int
	TotalFindings  int
}

type buildResultExtras struct {
	Baselines           map[string]string
	BaselineSamples     int
	EndpointReports     []endpointReport
	Findings            []model.Finding
	Summary             summaryView
	AttributionWarnings []string
}

// buildRunResult composes the model.RunResult that the reporter layer
// renders. It bridges the local endpointReport / summaryView types
// (kept for backward-compat with the legacy JSON shape) into the
// model.RunResult aggregate added in P4.
func buildRunResult(matrix *model.RoleMatrix, endpoints []*model.Endpoint, plan replay.Plan,
	responses []model.Response, start, end time.Time, rs model.RunSettings, extras buildResultExtras) *model.RunResult {

	out := &model.RunResult{
		Run: model.RunMeta{
			BaseURL:         matrix.Target.BaseURL,
			TotalEndpoints:  len(endpoints),
			TotalVariants:   len(plan.Variants),
			GeneratedTotal:  plan.TotalBefore,
			Capped:          plan.Capped,
			Start:           start,
			End:             end,
			BaselineSamples: extras.BaselineSamples,
			Baselines:       extras.Baselines,
			ToolVersion:     buildVersion,
			Settings: model.RunSetView{
				RatePerHost:   rs.RatePerHost,
				Concurrency:   rs.Concurrency,
				MaxVariants:   rs.MaxVariants,
				MaxBody:       rs.MaxBody,
				Timeout:       rs.Timeout.String(),
				NoLimit:       rs.NoLimit,
				Insecure:      rs.Insecure,
				MinConfidence: scanMinConfidence,
			},
		},
		Findings: extras.Findings,
		Summary: model.RunSummary{
			Verdicts:       extras.Summary.Verdicts,
			NoisyEndpoints: extras.Summary.NoisyEndpoints,
			ByClass:        extras.Summary.ByClass,
			BySeverity:     extras.Summary.BySeverity,
			TotalFindings:  extras.Summary.TotalFindings,
		},
		AttributionWarnings: extras.AttributionWarnings,
	}

	// Convert local endpointReport → model.EndpointReport, copying typed
	// notes into the model-side mirror struct (model can't import detect
	// without cycling).
	out.Endpoints = make([]model.EndpointReport, 0, len(extras.EndpointReports))
	for _, ep := range extras.EndpointReports {
		mer := model.EndpointReport{
			Key:                ep.Key,
			Method:             ep.Method,
			Host:               ep.Host,
			PathTemplate:       ep.PathTemplate,
			Owner:              ep.Owner,
			OwnerAttribution:   ep.OwnerAttribution,
			BaselineSamples:    ep.BaselineSamples,
			BaselineStatus:     ep.BaselineStatus,
			Stability:          ep.Stability,
			EffThreshold:       ep.EffThreshold,
			Noisy:              ep.Noisy,
			CalibrationSkipped: ep.CalibrationSkipped,
			BaselineFailed:     ep.BaselineFailed,
		}
		for _, n := range ep.Notes {
			mer.Notes = append(mer.Notes, model.EndpointNote{
				Code: string(n.Code), Message: n.Message, Payload: n.Payload,
			})
		}
		out.Endpoints = append(out.Endpoints, mer)
	}

	// Convert each (variant, response) into model.ResultEntry.
	out.Results = make([]model.ResultEntry, 0, len(plan.Variants))
	for i, v := range plan.Variants {
		var resp model.Response
		if i < len(responses) {
			resp = responses[i]
		}
		ident := ""
		if v.Identity != nil {
			ident = v.Identity.Name
		}
		urlStr := ""
		if v.Base != nil && v.Base.URL != nil {
			urlStr = v.Base.URL.String()
		}
		out.Results = append(out.Results, model.ResultEntry{
			Variant: model.VariantView{
				ID:          v.ID,
				EndpointKey: endpointKeyOfVariant(&plan.Variants[i]),
				Method:      v.Base.Method,
				URL:         urlStr,
				Mutation:    v.Mutation.Type,
				Class:       v.Mutation.Class,
				Identity:    ident,
				Detail:      v.Mutation.Detail,
			},
			Response: resp,
		})
	}
	return out
}

func writeDryRun(w io.Writer, plan replay.Plan, endpoints []*model.Endpoint, baselineSamples int) error {
	fmt.Fprintf(w, "dry-run plan: %d endpoints, %d variants, %d baseline samples per endpoint",
		len(endpoints), len(plan.Variants), baselineSamples)
	if plan.Capped {
		fmt.Fprintf(w, " (capped from %d)", plan.TotalBefore)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "ENDPOINT                                       OWNER       ATTRIBUTION              BASELINES")
	for _, ep := range endpoints {
		owner := "-"
		attr := "-"
		if ep.OwnerIdentity != nil {
			owner = ep.OwnerIdentity.Name
		}
		if ep.OwnerAttribution != "" {
			attr = ep.OwnerAttribution
		}
		fmt.Fprintf(w, "%-46s %-11s %-24s %d\n",
			endpointKeyOf(ep), owner, attr, baselineSamples)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "ID                METHOD  MUTATION         IDENTITY     URL")
	for _, v := range plan.Variants {
		ident := "-"
		if v.Identity != nil {
			ident = v.Identity.Name
		}
		urlStr := ""
		if v.Base != nil && v.Base.URL != nil {
			urlStr = v.Base.URL.String()
		}
		fmt.Fprintf(w, "%-16s  %-6s  %-15s  %-10s  %s\n",
			v.ID, v.Base.Method, v.Mutation.Type, ident, urlStr)
	}
	return nil
}

// clusterEnumerateFindings collapses multiple enumerate-id findings for the
// same endpoint into a single clustered idor finding. Each original finding
// becomes a note line in the clustered finding's Evidence.Notes so the probe
// details are not lost. Non-enumerate-id findings pass through unchanged.
//
// Clustering rules:
//   - Group by EndpointKey.
//   - Within a group, take the highest-confidence finding as the representative
//     (it carries the most informative Evidence baseline/variant status).
//   - Append one "hit: probe_id=<id> status=<s>" note per grouped finding.
//   - The clustered finding ID is re-derived from the endpoint key alone so it
//     stays stable across sweeps of different sizes.
func clusterEnumerateFindings(findings []model.Finding) []model.Finding {
	// Fast path: no enumerate-id findings at all.
	hasEnum := false
	for _, f := range findings {
		if f.Mutation == "enumerate-id" {
			hasEnum = true
			break
		}
	}
	if !hasEnum {
		return findings
	}

	// Separate enumerate-id from other findings.
	var enumFindings []model.Finding
	var others []model.Finding
	for _, f := range findings {
		if f.Mutation == "enumerate-id" {
			enumFindings = append(enumFindings, f)
		} else {
			others = append(others, f)
		}
	}

	// Group enumerate-id findings by endpoint key.
	type group struct {
		best   model.Finding
		probes []model.Finding
	}
	groups := make(map[string]*group)
	order := []string{} // preserve first-seen order for deterministic output
	for _, f := range enumFindings {
		g, ok := groups[f.EndpointKey]
		if !ok {
			g = &group{}
			groups[f.EndpointKey] = g
			order = append(order, f.EndpointKey)
		}
		if f.Confidence > g.best.Confidence {
			g.best = f
		}
		g.probes = append(g.probes, f)
	}

	// Build one clustered finding per endpoint group.
	clustered := make([]model.Finding, 0, len(groups))
	for _, key := range order {
		g := groups[key]
		cf := g.best
		notes := make([]string, 0, len(g.probes)+1)
		notes = append(notes, fmt.Sprintf("enumerate-id sweep: %d responsive probes", len(g.probes)))
		// Sort probes by probe_id for a deterministic note order.
		sort.Slice(g.probes, func(i, j int) bool {
			return g.probes[i].Evidence.VariantStatus < g.probes[j].Evidence.VariantStatus ||
				(g.probes[i].Evidence.VariantStatus == g.probes[j].Evidence.VariantStatus &&
					probeIDStr(g.probes[i]) < probeIDStr(g.probes[j]))
		})
		for _, p := range g.probes {
			notes = append(notes, fmt.Sprintf("hit: probe_id=%s status=%d similarity=%.2f",
				probeIDStr(p), p.Evidence.VariantStatus, p.Evidence.SimilarityScore))
		}
		cf.Evidence.Notes = notes
		// Override ID with a stable key derived only from the endpoint so
		// repeated sweeps produce the same finding ID.
		cf.ID = clusterFindingID(key)
		cf.VariantID = "clustered"
		clustered = append(clustered, cf)
	}

	return append(others, clustered...)
}

// probeIDStr extracts the probe_id detail from a Finding's Variant, falling
// back to the VariantID when the detail is unavailable.
func probeIDStr(f model.Finding) string {
	if f.Variant != nil && f.Variant.Mutation.Detail != nil {
		if v, ok := f.Variant.Mutation.Detail["probe_id"]; ok {
			return v
		}
	}
	return f.VariantID
}

// clusterFindingID produces a stable 16-hex-char ID for a clustered
// enumerate-id finding, keyed only on the endpoint so it is stable across
// sweeps of different sizes.
func clusterFindingID(endpointKey string) string {
	h := sha256.Sum256([]byte(endpointKey + "|enumerate-id|clustered"))
	return hex.EncodeToString(h[:])[:16]
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	var mult int64 = 1
	switch {
	case strings.HasSuffix(s, "GB"):
		mult = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "MB"):
		mult = 1024 * 1024
		s = strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "KB"):
		mult = 1024
		s = strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}
	s = strings.TrimSpace(s)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("size must be >= 0")
	}
	return n * mult, nil
}

// buildEvaluator returns the Evaluator selected by the --evaluator flag.
func buildEvaluator(name string, matrix *model.RoleMatrix) (detect.Evaluator, error) {
	switch name {
	case "comparative", "":
		return detect.ComparativeEvaluator{}, nil
	case "assertion":
		if matrix == nil || len(matrix.Assertions) == 0 {
			return nil, fmt.Errorf("scan: --evaluator assertion requires an assertions block in the matrix YAML")
		}
		return detect.AssertionEvaluator{}, nil
	case "both":
		return detect.BothEvaluator{}, nil
	default:
		return nil, fmt.Errorf("scan: --evaluator: unknown value %q (want: comparative|assertion|both)", name)
	}
}

// buildRegistry returns the mutator registry, optionally replacing
// jwt-hmac-crack's wordlist with the contents of wordlistPath, enabling
// the EnumerateID mutator when enumerateN > 0, and enabling the JWTAuth
// (--jwt-attack) mutator when jwtAttack is true. Both EnumerateID and
// JWTAuth are always registered but inert in their disabled state, so the
// canonical DefaultRegistry order (and the order test) stays unchanged.
func buildRegistry(wordlistPath string, enumerateN int, jwtAttack bool) (*mutate.Registry, error) {
	enumMutator := mutate.EnumerateID{N: enumerateN}
	jwtAuthMutator := mutate.JWTAuth{Enabled: jwtAttack}

	if wordlistPath == "" {
		// Extend the default registry with EnumerateID + JWTAuth (both
		// no-op in their disabled state).
		base := mutate.DefaultRegistry()
		all := append(base.All(), enumMutator, jwtAuthMutator)
		return mutate.NewRegistry(all...), nil
	}
	data, err := os.ReadFile(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("scan: --jwt-wordlist: %w", err)
	}
	var words []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		words = append(words, line)
	}
	return mutate.NewRegistry(
		mutate.StripAuth{},
		mutate.SwapIdentity{},
		mutate.DowngradeRole{},
		mutate.DropCookie{},
		mutate.StripToken{},
		mutate.SwapObject{},
		mutate.JWTAlgNone{},
		mutate.JWTSigStrip{},
		mutate.JWTClaimTamper{},
		mutate.JWTResignWeakKey{},
		mutate.JWTAlgConfusion{},
		mutate.JWTKidInjection{},
		mutate.JWTJwksSpoof{},
		mutate.JWTHmacCrack{Wordlist: words},
		enumMutator,
		jwtAuthMutator,
	), nil
}

// Reference to silence "unused import" for net/http when scan-related code
// doesn't directly reference it; the package is used through model.Response.
var _ = http.MethodGet
