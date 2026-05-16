package cli

import (
	"context"
	"encoding/json"
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
	scanCmd.Flags().StringVar(&scanFormat, "format", "auto", "input format: har | curl | auto")
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
}

func runScan(cmd *cobra.Command, args []string) error {
	if scanMatrix == "" {
		return fmt.Errorf("scan: --matrix is required")
	}
	if len(args) != 1 {
		return fmt.Errorf("scan: exactly one input file is required")
	}
	input := args[0]

	matrix, err := config.LoadFile(scanMatrix)
	if err != nil {
		return err
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

	reg := mutate.DefaultRegistry()
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
	ev := detect.ComparativeEvaluator{}
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

		// Per-endpoint notes — start with calibration notes, add refresh
		// failures detected in the variant responses for this endpoint.
		notes := append([]string{}, cal.Notes...)
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
			notes = append(notes, "refresh-failed: identity "+n+" variants marked inconclusive")
		}
		if omittedByMinConf > 0 {
			notes = append(notes, fmt.Sprintf("min-confidence: %d finding(s) omitted from array (still counted in summary)", omittedByMinConf))
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

	// Populate Mutation.Class on every variant so the JSON output sees it
	// even for non-finding variants (Gate-D additive #3).
	for i := range plan.Variants {
		plan.Variants[i].Mutation.Class = detect.MutatorClass(plan.Variants[i].Mutation.Type)
	}

	out := buildResultDoc(matrix, endpoints, plan, responses, start, end, rs, buildResultExtras{
		Baselines:         baselineMap,
		BaselineSamples:   baselineSamples,
		EndpointReports:   endpointReports,
		Findings:          allFindings,
		Summary:           summaryView{
			Verdicts:         verdictCounts,
			NoisyEndpoints:   noisyCount,
			ByClass:          byClass,
			BySeverity:       bySeverity,
			TotalFindings:    len(allFindings),
		},
		AttributionWarnings: attributionWarnings,
	})

	w := cmd.OutOrStdout()
	if scanOut != "" {
		fh, err := os.Create(scanOut)
		if err != nil {
			return fmt.Errorf("scan: create %s: %w", scanOut, err)
		}
		defer fh.Close()
		w = fh
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

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

// --- output shapes ---

type runMeta struct {
	BaseURL         string            `json:"base_url,omitempty"`
	TotalEndpoints  int               `json:"total_endpoints"`
	TotalVariants   int               `json:"total_variants"`
	GeneratedTotal  int               `json:"variants_generated_before_cap"`
	Capped          bool              `json:"capped"`
	Settings        runSetView        `json:"settings"`
	Start           time.Time         `json:"start"`
	End             time.Time         `json:"end"`
	BaselineSamples int               `json:"baseline_samples"`
	Baselines       map[string]string `json:"baselines,omitempty"`
}

type runSetView struct {
	RatePerHost   float64 `json:"rate_per_host"`
	Concurrency   int     `json:"concurrency"`
	MaxVariants   int     `json:"max_variants"`
	MaxBody       int64   `json:"max_body"`
	Timeout       string  `json:"timeout"`
	NoLimit       bool    `json:"no_limit"`
	Insecure      bool    `json:"insecure"`
	MinConfidence float64 `json:"min_confidence"`
}

type variantView struct {
	ID          string            `json:"id"`
	EndpointKey string            `json:"endpoint_key"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Mutation    string            `json:"mutation"`
	Class       string            `json:"class,omitempty"`
	Identity    string            `json:"identity,omitempty"`
	Detail      map[string]string `json:"detail,omitempty"`
}

type resultEntry struct {
	Variant  variantView    `json:"variant"`
	Response model.Response `json:"response"`
}

type endpointReport struct {
	Key                string   `json:"key"`
	Method             string   `json:"method"`
	Host               string   `json:"host"`
	PathTemplate       string   `json:"path_template"`
	Owner              string   `json:"owner,omitempty"`
	OwnerAttribution   string   `json:"owner_attribution,omitempty"`
	BaselineSamples    int      `json:"baseline_samples"`
	BaselineStatus     int      `json:"baseline_status"`
	Stability          float64  `json:"stability"`
	EffThreshold       float64  `json:"eff_threshold"`
	Noisy              bool     `json:"noisy"`
	CalibrationSkipped bool     `json:"calibration_skipped"`
	BaselineFailed     bool     `json:"baseline_failed"`
	Notes              []string `json:"notes,omitempty"`
}

type summaryView struct {
	Verdicts       map[string]int `json:"verdicts"`
	NoisyEndpoints int            `json:"noisy_endpoints"`
	ByClass        map[string]int `json:"by_class"`
	BySeverity     map[string]int `json:"by_severity"`
	TotalFindings  int            `json:"total_findings"`
}

type resultDoc struct {
	Run                 runMeta          `json:"run"`
	Endpoints           []endpointReport `json:"endpoints"`
	Results             []resultEntry    `json:"results"`
	Findings            []model.Finding  `json:"findings"`
	Summary             summaryView      `json:"summary"`
	AttributionWarnings []string         `json:"attribution_warnings,omitempty"`
}

type buildResultExtras struct {
	Baselines           map[string]string
	BaselineSamples     int
	EndpointReports     []endpointReport
	Findings            []model.Finding
	Summary             summaryView
	AttributionWarnings []string
}

func buildResultDoc(matrix *model.RoleMatrix, endpoints []*model.Endpoint, plan replay.Plan,
	responses []model.Response, start, end time.Time, rs model.RunSettings, extras buildResultExtras) resultDoc {
	doc := resultDoc{
		Run: runMeta{
			BaseURL:         matrix.Target.BaseURL,
			TotalEndpoints:  len(endpoints),
			TotalVariants:   len(plan.Variants),
			GeneratedTotal:  plan.TotalBefore,
			Capped:          plan.Capped,
			Start:           start,
			End:             end,
			BaselineSamples: extras.BaselineSamples,
			Baselines:       extras.Baselines,
			Settings: runSetView{
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
		Endpoints:           extras.EndpointReports,
		Findings:            extras.Findings,
		Summary:             extras.Summary,
		AttributionWarnings: extras.AttributionWarnings,
	}
	doc.Results = make([]resultEntry, 0, len(plan.Variants))
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
		doc.Results = append(doc.Results, resultEntry{
			Variant: variantView{
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
	return doc
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

// Reference to silence "unused import" for net/http when scan-related code
// doesn't directly reference it; the package is used through model.Response.
var _ = http.MethodGet
