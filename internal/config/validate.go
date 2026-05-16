package config

import (
	"fmt"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// ValidationError aggregates one or more validation failures so that users
// see every problem in their matrix on a single run rather than having to
// fix them one at a time.
type ValidationError struct {
	Errors []string
}

func (v *ValidationError) Error() string {
	if v == nil || len(v.Errors) == 0 {
		return "config: no errors"
	}
	return "config: validation failed:\n  - " + strings.Join(v.Errors, "\n  - ")
}

var validFrom = map[string]struct{}{
	"body-json":  {},
	"body-regex": {},
	"header":     {},
	"cookie":     {},
}

var validInto = map[string]struct{}{
	"header": {},
	"cookie": {},
	"query":  {},
	"body-json": {},
}

// Validate returns a *ValidationError listing every problem with m, or nil
// if the matrix is well-formed.
func Validate(m *model.RoleMatrix) error {
	v := &ValidationError{}

	if m.Version != "1" {
		v.add("version must equal \"1\" (got %q)", m.Version)
	}
	if len(m.Identities) == 0 {
		v.add("at least one identity is required")
	}
	seen := make(map[string]int)
	for i, id := range m.Identities {
		prefix := fmt.Sprintf("identities[%d]", i)
		if id.Name == "" {
			v.add("%s.name is required", prefix)
		} else {
			if prev, dup := seen[id.Name]; dup {
				v.add("%s.name duplicates identities[%d].name (%q)", prefix, prev, id.Name)
			}
			seen[id.Name] = i
		}
		if id.Role == "" {
			v.add("%s.role is required", prefix)
		}
		if id.Rank < 0 {
			v.add("%s.rank must be >= 0 (got %d)", prefix, id.Rank)
		}
		if id.Creds != nil {
			hasAny := len(id.Creds.Cookies) > 0 ||
				len(id.Creds.Headers) > 0 ||
				id.Creds.Bearer != "" ||
				id.Creds.Basic != nil
			if !hasAny {
				v.add("%s.creds must contain at least one of cookies/headers/bearer/basic", prefix)
			}
		}
		// markers (D20): optional; if present, each must be non-empty.
		for j, mk := range id.Markers {
			if mk == "" {
				v.add("%s.markers[%d] must be non-empty", prefix, j)
			}
		}
		if id.Refresh != nil {
			for j, ex := range id.Refresh.Extract {
				exPrefix := fmt.Sprintf("%s.refresh.extract[%d]", prefix, j)
				if _, ok := validFrom[ex.From]; !ok {
					v.add("%s.from must be one of body-json|body-regex|header|cookie (got %q)", exPrefix, ex.From)
				}
				if _, ok := validInto[ex.Inject.Into]; !ok {
					v.add("%s.inject.into must be one of header|cookie|query|body-json (got %q)", exPrefix, ex.Inject.Into)
				}
			}
		}
	}

	for i, pat := range m.Scope.Include {
		if err := validateGlob(pat); err != nil {
			v.add("scope.include[%d] %q: %v", i, pat, err)
		}
	}
	for i, pat := range m.Scope.Exclude {
		if err := validateGlob(pat); err != nil {
			v.add("scope.exclude[%d] %q: %v", i, pat, err)
		}
	}

	if m.Settings.RatePerHost <= 0 {
		v.add("settings.rate_per_host must be > 0 (got %v)", m.Settings.RatePerHost)
	}
	if m.Settings.Concurrency < 1 {
		v.add("settings.concurrency must be >= 1 (got %d)", m.Settings.Concurrency)
	}
	if m.Settings.Timeout <= 0 {
		v.add("settings.timeout must be > 0 (got %v)", m.Settings.Timeout)
	}

	if len(v.Errors) == 0 {
		return nil
	}
	return v
}

func (v *ValidationError) add(format string, args ...any) {
	v.Errors = append(v.Errors, fmt.Sprintf(format, args...))
}

// validateGlob is a minimal sanity check for our custom doublestar dialect.
// We just ensure the pattern is non-empty and contains no obviously
// malformed runs like `***`. Compilation per se is trivial because the
// matcher streams.
func validateGlob(pat string) error {
	if pat == "" {
		return fmt.Errorf("empty pattern")
	}
	if strings.Contains(pat, "***") {
		return fmt.Errorf("invalid wildcard sequence %q", "***")
	}
	return nil
}

// MatchGlob reports whether path matches a pattern using our minimal
// doublestar dialect: `*` matches any non-slash chars, `**` matches any
// chars including slashes, `?` matches a single non-slash char. Anchored
// to the full path (no implicit substring matching).
func MatchGlob(pattern, path string) bool {
	return matchGlob(pattern, path)
}

// matchGlob is a small recursive matcher. Patterns are short and paths
// are bounded, so the simple recursion is fine and far clearer than the
// iterative backtracker.
func matchGlob(pat, s string) bool {
	for {
		if len(pat) == 0 {
			return len(s) == 0
		}
		// Doublestar: matches any sequence including '/'.
		if len(pat) >= 2 && pat[0] == '*' && pat[1] == '*' {
			rest := pat[2:]
			// Greedy: try matching the remainder at every position of s.
			for i := 0; i <= len(s); i++ {
				if matchGlob(rest, s[i:]) {
					return true
				}
			}
			return false
		}
		// Single star: matches any sequence excluding '/'.
		if pat[0] == '*' {
			rest := pat[1:]
			for i := 0; i <= len(s); i++ {
				if matchGlob(rest, s[i:]) {
					return true
				}
				if i < len(s) && s[i] == '/' {
					break
				}
			}
			return false
		}
		// '?' single non-slash char.
		if pat[0] == '?' {
			if len(s) == 0 || s[0] == '/' {
				return false
			}
			pat = pat[1:]
			s = s[1:]
			continue
		}
		// Literal.
		if len(s) == 0 || pat[0] != s[0] {
			return false
		}
		pat = pat[1:]
		s = s[1:]
	}
}
