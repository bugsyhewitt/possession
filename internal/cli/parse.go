package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/bugsyhewitt/possession/internal/config"
	"github.com/bugsyhewitt/possession/internal/model"
	"github.com/bugsyhewitt/possession/internal/normalize"
	"github.com/bugsyhewitt/possession/internal/parse"
)

var (
	parseFormat string
	parseScope  string
	parseJSON   bool
)

func init() {
	parseCmd.Flags().StringVar(&parseFormat, "format", "auto",
		"input format: har | curl | auto")
	parseCmd.Flags().StringVar(&parseScope, "scope", "",
		"path to a role-matrix YAML; its scope.include/exclude is applied as a filter")
	parseCmd.Flags().BoolVar(&parseJSON, "json", false,
		"emit machine-readable JSON instead of the human table")
}

var parseCmd = &cobra.Command{
	Use:   "parse <input>",
	Short: "Parse a HAR or curl capture and print deduplicated endpoints.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := args[0]
		format, err := detectFormat(input, parseFormat)
		if err != nil {
			return err
		}

		f, err := os.Open(input)
		if err != nil {
			return fmt.Errorf("parse: open %s: %w", input, err)
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
		default:
			return fmt.Errorf("parse: unknown format %q", format)
		}
		if err != nil {
			return err
		}

		normalize.Apply(requests)

		if parseScope != "" {
			matrix, err := config.LoadFile(parseScope)
			if err != nil {
				return err
			}
			requests = applyScope(requests, matrix.Scope)
		}

		endpoints := normalize.Dedup(requests)

		if parseJSON {
			return writeJSON(cmd.OutOrStdout(), endpoints)
		}
		return writeTable(cmd.OutOrStdout(), endpoints)
	},
}

// detectFormat resolves --format=auto by extension and then by content
// sniffing (first non-space byte).
func detectFormat(path, requested string) (string, error) {
	switch strings.ToLower(requested) {
	case "har", "curl":
		return strings.ToLower(requested), nil
	case "", "auto":
		// fall through
	default:
		return "", fmt.Errorf("parse: unknown --format %q", requested)
	}

	if strings.EqualFold(filepath.Ext(path), ".har") {
		return "har", nil
	}
	// Sniff: read up to 256 bytes, find the first non-space byte.
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("parse: sniff %s: %w", path, err)
	}
	defer f.Close()
	r := bufio.NewReader(f)
	buf, _ := r.Peek(256)
	for _, b := range buf {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		if b == '{' {
			return "har", nil
		}
		if b == 'c' || b == 'C' {
			return "curl", nil
		}
		break
	}
	return "", fmt.Errorf("parse: could not auto-detect format for %s (pass --format)", path)
}

func applyScope(reqs []*model.CapturedRequest, scope model.ScopeConfig) []*model.CapturedRequest {
	if len(scope.Include) == 0 && len(scope.Exclude) == 0 {
		return reqs
	}
	out := reqs[:0]
	for _, r := range reqs {
		if r == nil || r.URL == nil {
			continue
		}
		p := r.URL.Path
		if len(scope.Include) > 0 {
			matched := false
			for _, pat := range scope.Include {
				if config.MatchGlob(pat, p) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		excluded := false
		for _, pat := range scope.Exclude {
			if config.MatchGlob(pat, p) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		out = append(out, r)
	}
	return out
}

// jsonEndpoint is the on-wire shape for --json. Keeping it separate from
// model.Endpoint avoids leaking internal pointers and lets us evolve the
// CLI contract independently of the domain model.
type jsonEndpoint struct {
	Method       string `json:"method"`
	Host         string `json:"host"`
	PathTemplate string `json:"path_template"`
	Samples      int    `json:"samples"`
}

func writeJSON(w io.Writer, endpoints []*model.Endpoint) error {
	out := make([]jsonEndpoint, 0, len(endpoints))
	for _, e := range endpoints {
		out = append(out, jsonEndpoint{
			Method:       e.Method,
			Host:         e.Host,
			PathTemplate: e.PathTemplate,
			Samples:      len(e.Samples),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeTable(w io.Writer, endpoints []*model.Endpoint) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "METHOD\tPATH-TEMPLATE\tSAMPLES\tHOST")
	for _, e := range endpoints {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n",
			e.Method, e.PathTemplate, len(e.Samples), e.Host)
	}
	return tw.Flush()
}
