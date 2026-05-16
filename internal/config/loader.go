// Package config loads and validates a possession role-matrix YAML file.
//
// Glob matching note: scope.include/exclude patterns use a small custom
// matcher that supports `*` (any non-slash chars), `**` (any chars
// including slashes), and `?` (single non-slash char). No square-bracket
// classes. This is sufficient for path scoping and avoids pulling in a
// glob dependency.
package config

import (
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bugsyhewitt/possession/internal/model"
)

// raw is the on-disk YAML shape. It is intentionally separate from
// model.RoleMatrix so that schema/version drift can be absorbed here
// without leaking into the domain types.
type raw struct {
	Version    string `yaml:"version"`
	Target     struct {
		BaseURL string `yaml:"base_url"`
	} `yaml:"target"`
	Identities []rawIdentity `yaml:"identities"`
	Scope      struct {
		Include []string `yaml:"include"`
		Exclude []string `yaml:"exclude"`
	} `yaml:"scope"`
	Settings struct {
		RatePerHost     float64 `yaml:"rate_per_host"`
		Concurrency     int     `yaml:"concurrency"`
		Timeout         string  `yaml:"timeout"`
		FollowRedirects bool    `yaml:"follow_redirects"`
	} `yaml:"settings"`
}

type rawIdentity struct {
	Name    string          `yaml:"name"`
	Role    string          `yaml:"role"`
	Rank    int             `yaml:"rank"`
	Creds   *rawCredentials `yaml:"creds"`
	Refresh *rawRefresh     `yaml:"refresh"`
}

type rawCredentials struct {
	Cookies map[string]string `yaml:"cookies"`
	Headers map[string]string `yaml:"headers"`
	Bearer  string            `yaml:"bearer"`
	Basic   *rawBasic         `yaml:"basic"`
}

type rawBasic struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type rawRefresh struct {
	Request struct {
		Method  string            `yaml:"method"`
		URL     string            `yaml:"url"`
		Headers map[string]string `yaml:"headers"`
		Body    string            `yaml:"body"`
	} `yaml:"request"`
	Extract []rawExtraction `yaml:"extract"`
}

type rawExtraction struct {
	Name   string `yaml:"name"`
	From   string `yaml:"from"`
	Expr   string `yaml:"expr"`
	Inject struct {
		Into string `yaml:"into"`
		Key  string `yaml:"key"`
	} `yaml:"inject"`
}

// LoadFile reads, parses, and validates a role-matrix YAML file. It
// returns the populated model.RoleMatrix and an error describing every
// validation failure (aggregated via *ValidationError).
func LoadFile(path string) (*model.RoleMatrix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer f.Close()
	return Load(f)
}

// Load parses and validates a role-matrix YAML stream.
func Load(r io.Reader) (*model.RoleMatrix, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("config: read: %w", err)
	}
	var rm raw
	if err := yaml.Unmarshal(data, &rm); err != nil {
		return nil, fmt.Errorf("config: yaml: %w", err)
	}

	// Translate to the domain type, deferring validation. Validation runs
	// against the domain shape so that errors reference the same fields
	// the rest of the system uses.
	matrix, parseErr := toMatrix(rm)
	if parseErr != nil {
		return nil, parseErr
	}
	if verr := Validate(matrix); verr != nil {
		return nil, verr
	}
	return matrix, nil
}

func toMatrix(rm raw) (*model.RoleMatrix, error) {
	out := &model.RoleMatrix{
		Version: rm.Version,
		Target:  model.TargetConfig{BaseURL: rm.Target.BaseURL},
		Scope: model.ScopeConfig{
			Include: rm.Scope.Include,
			Exclude: rm.Scope.Exclude,
		},
	}

	// Settings — timeout is parsed up front so we can surface a clean
	// error before deeper validation runs.
	if rm.Settings.Timeout != "" {
		d, err := time.ParseDuration(rm.Settings.Timeout)
		if err != nil {
			return nil, fmt.Errorf("config: settings.timeout: invalid duration %q: %w", rm.Settings.Timeout, err)
		}
		out.Settings.Timeout = d
	}
	out.Settings.RatePerHost = rm.Settings.RatePerHost
	out.Settings.Concurrency = rm.Settings.Concurrency
	out.Settings.FollowRedirects = rm.Settings.FollowRedirects

	for _, ri := range rm.Identities {
		ident := model.Identity{
			Name: ri.Name,
			Role: ri.Role,
			Rank: ri.Rank,
		}
		if ri.Creds != nil {
			ident.Creds = &model.Credentials{
				Cookies: ri.Creds.Cookies,
				Headers: ri.Creds.Headers,
				Bearer:  ri.Creds.Bearer,
			}
			if ri.Creds.Basic != nil {
				ident.Creds.Basic = &model.BasicAuth{
					Username: ri.Creds.Basic.Username,
					Password: ri.Creds.Basic.Password,
				}
			}
		}
		if ri.Refresh != nil {
			rh := &model.RefreshHook{
				Request: model.RawRequest{
					Method:  ri.Refresh.Request.Method,
					URL:     ri.Refresh.Request.URL,
					Headers: ri.Refresh.Request.Headers,
					Body:    ri.Refresh.Request.Body,
				},
			}
			for _, ex := range ri.Refresh.Extract {
				rh.Extract = append(rh.Extract, model.Extraction{
					Name: ex.Name,
					From: ex.From,
					Expr: ex.Expr,
					Inject: model.Injection{
						Into: ex.Inject.Into,
						Key:  ex.Inject.Key,
					},
				})
			}
			ident.Refresh = rh
		}
		out.Identities = append(out.Identities, ident)
	}
	return out, nil
}
