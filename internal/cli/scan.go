package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bugsyhewitt/possession/internal/config"
	"github.com/bugsyhewitt/possession/internal/model"
	"github.com/bugsyhewitt/possession/internal/mutate"
	"github.com/bugsyhewitt/possession/internal/normalize"
	"github.com/bugsyhewitt/possession/internal/parse"
	"github.com/bugsyhewitt/possession/internal/replay"
)

var (
	scanMatrix      string
	scanFormat      string
	scanRate        float64
	scanConcurrency int
	scanMaxVariants int
	scanMaxBody     string
	scanNoLimit     bool
	scanInsecure    bool
	scanOut         string
	scanDryRun      bool
)

// scanCmd is Packet 2's functional scan command. It parses an input
// capture, generates a deterministic variant plan, optionally fires it
// against the live target, and writes JSON results. No detection logic —
// that is Packet 3's job.
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
}

// resetScanFlags zeroes scan-related package state so tests can re-invoke
// the command cleanly. Mirrors what runCmd does for parse-side flags.
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

	// Resolve flag defaults from matrix.settings.
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

	// Loud warnings (D15, --insecure).
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

	reg := mutate.DefaultRegistry()
	plan := replay.Generate(endpoints, matrix, reg, scanMaxVariants)
	if plan.Capped {
		fmt.Fprintf(stderr,
			"!!! variant cap hit: generated %d but capped at %d. Increase --max-variants to see them all.\n",
			plan.TotalBefore, scanMaxVariants)
	}

	if scanDryRun {
		return writeDryRun(cmd.OutOrStdout(), plan, endpoints)
	}

	// Apply resolved settings into the engine.
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
	responses := engine.Run(ctx, plan)
	end := time.Now()

	out := buildResultDoc(matrix, endpoints, plan, responses, start, end, rs)
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

// --- output shapes ---

type runMeta struct {
	BaseURL        string     `json:"base_url,omitempty"`
	TotalEndpoints int        `json:"total_endpoints"`
	TotalVariants  int        `json:"total_variants"`
	GeneratedTotal int        `json:"variants_generated_before_cap"`
	Capped         bool       `json:"capped"`
	Settings       runSetView `json:"settings"`
	Start          time.Time  `json:"start"`
	End            time.Time  `json:"end"`
}

type runSetView struct {
	RatePerHost float64 `json:"rate_per_host"`
	Concurrency int     `json:"concurrency"`
	MaxVariants int     `json:"max_variants"`
	MaxBody     int64   `json:"max_body"`
	Timeout     string  `json:"timeout"`
	NoLimit     bool    `json:"no_limit"`
	Insecure    bool    `json:"insecure"`
}

type variantView struct {
	ID       string            `json:"id"`
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Mutation string            `json:"mutation"`
	Identity string            `json:"identity,omitempty"`
	Detail   map[string]string `json:"detail,omitempty"`
}

type resultEntry struct {
	Variant  variantView    `json:"variant"`
	Response model.Response `json:"response"`
}

type resultDoc struct {
	Run     runMeta       `json:"run"`
	Results []resultEntry `json:"results"`
}

func buildResultDoc(matrix *model.RoleMatrix, endpoints []*model.Endpoint, plan replay.Plan,
	responses []model.Response, start, end time.Time, rs model.RunSettings) resultDoc {
	doc := resultDoc{
		Run: runMeta{
			BaseURL:        matrix.Target.BaseURL,
			TotalEndpoints: len(endpoints),
			TotalVariants:  len(plan.Variants),
			GeneratedTotal: plan.TotalBefore,
			Capped:         plan.Capped,
			Start:          start,
			End:            end,
			Settings: runSetView{
				RatePerHost: rs.RatePerHost,
				Concurrency: rs.Concurrency,
				MaxVariants: rs.MaxVariants,
				MaxBody:     rs.MaxBody,
				Timeout:     rs.Timeout.String(),
				NoLimit:     rs.NoLimit,
				Insecure:    rs.Insecure,
			},
		},
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
				ID:       v.ID,
				Method:   v.Base.Method,
				URL:      urlStr,
				Mutation: v.Mutation.Type,
				Identity: ident,
				Detail:   v.Mutation.Detail,
			},
			Response: resp,
		})
	}
	return doc
}

func writeDryRun(w io.Writer, plan replay.Plan, endpoints []*model.Endpoint) error {
	fmt.Fprintf(w, "dry-run plan: %d endpoints, %d variants", len(endpoints), len(plan.Variants))
	if plan.Capped {
		fmt.Fprintf(w, " (capped from %d)", plan.TotalBefore)
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

// parseSize converts strings like "5MB", "10KB", "1024" to bytes.
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
