package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// TestSampleOutput_VulnApp is a small artifact-producing test that
// writes a trimmed JSON findings+summary block from a vulnapp scan to
// stdout when run with `go test -run SampleOutput -v`. Skipped unless
// POSSESSION_EMIT_SAMPLE=1 is set so the normal test run stays quiet.
func TestSampleOutput_VulnApp(t *testing.T) {
	if os.Getenv("POSSESSION_EMIT_SAMPLE") == "" {
		t.Skip("set POSSESSION_EMIT_SAMPLE=1 to emit sample output")
	}
	srv := startVulnApp(t)
	defer srv.Close()
	defs := []endpointDef{
		{"GET", "/users/alice", "/users/{id}"},
		{"GET", "/profile", "/profile"},
		{"POST", "/admin/promote", "/admin/promote"},
	}
	findings, _, verdictCounts, noisy := runCorpus(t, srv, defs)
	type out struct {
		Findings        []findingView  `json:"findings"`
		VerdictCounts   map[string]int `json:"verdicts"`
		NoisyEndpoints  int            `json:"noisy_endpoints"`
		TotalFindings   int            `json:"total_findings"`
	}
	fs := make([]findingView, 0, len(findings))
	for _, f := range findings {
		fs = append(fs, findingView{
			ID: f.ID, EndpointKey: f.EndpointKey, Mutation: f.Mutation,
			Identity: f.Identity, Class: f.Class, Verdict: f.Verdict,
			Confidence: f.Confidence, Severity: f.Severity, ASVS: f.ASVS,
			BaselineStatus: f.Evidence.BaselineStatus,
			VariantStatus: f.Evidence.VariantStatus,
			Similarity: f.Evidence.SimilarityScore,
			Notes: f.Evidence.Notes,
		})
	}
	b, _ := json.MarshalIndent(out{
		Findings: fs, VerdictCounts: verdictCounts,
		NoisyEndpoints: noisy, TotalFindings: len(findings),
	}, "", "  ")
	fmt.Println(string(b))
}

type findingView struct {
	ID             string   `json:"id"`
	EndpointKey    string   `json:"endpoint_key"`
	Mutation       string   `json:"mutation"`
	Identity       string   `json:"identity,omitempty"`
	Class          string   `json:"class"`
	Verdict        string   `json:"verdict"`
	Confidence     float64  `json:"confidence"`
	Severity       string   `json:"severity"`
	ASVS           []string `json:"asvs"`
	BaselineStatus int      `json:"baseline_status"`
	VariantStatus  int      `json:"variant_status"`
	Similarity     float64  `json:"similarity"`
	Notes          []string `json:"notes,omitempty"`
}
