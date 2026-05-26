// Package suppress implements the possession.allowlist suppression file.
//
// A suppression file is a YAML document that lists finding IDs to exclude
// from scan output. Finding IDs are deterministic 16-hex-char SHA256 digests
// (see internal/detect/finding.go findingID). Once a finding is acknowledged
// and added to the allowlist, subsequent runs with --allowlist will not
// surface it — only NEW findings appear.
//
// File format (YAML):
//
//	version: "1"
//	description: "Optional human note about this allowlist."
//	entries:
//	  - id: "a1b2c3d4e5f60718"
//	    added_at: "2026-05-26T18:00:00Z"
//	    added_by: "alice"
//	    note: "Known IDOR on /admin/users/{id} — accepted risk, internal-only endpoint."
//
// # Rules
//
//   - Entries without a note are valid (note is optional).
//   - Entries with duplicate IDs are collapsed on load (first declaration wins).
//   - An empty entries list is valid (no suppression).
//   - Unknown YAML keys are ignored (forward-compatible).
//
// # Usage
//
//	al, err := suppress.LoadFile("possession.allowlist")
//	filtered := suppress.Apply(allFindings, al)
//
//	// To write/update:
//	merged := suppress.Merge(existing, suppress.FromFindings(newFindings, "ci", ""))
//	err = suppress.WriteFile("possession.allowlist", merged)
package suppress

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bugsyhewitt/possession/internal/model"
)

// Allowlist is the in-memory representation of a suppression file.
type Allowlist struct {
	Version     string  `yaml:"version"`
	Description string  `yaml:"description,omitempty"`
	Entries     []Entry `yaml:"entries"`
}

// Entry is one suppressed finding ID.
type Entry struct {
	ID      string `yaml:"id"`
	AddedAt string `yaml:"added_at,omitempty"`
	AddedBy string `yaml:"added_by,omitempty"`
	Note    string `yaml:"note,omitempty"`
}

// Load parses the YAML content of an allowlist. Returns an empty Allowlist
// (no entries) on empty input — callers do not need to special-case empty
// files.
func Load(data []byte) (*Allowlist, error) {
	if len(data) == 0 {
		return &Allowlist{Version: "1"}, nil
	}
	al := &Allowlist{}
	if err := yaml.Unmarshal(data, al); err != nil {
		return nil, fmt.Errorf("suppress: parse allowlist: %w", err)
	}
	if al.Version == "" {
		al.Version = "1"
	}
	// Deduplicate: first declaration of an ID wins.
	seen := make(map[string]struct{}, len(al.Entries))
	deduped := al.Entries[:0]
	for _, e := range al.Entries {
		if _, ok := seen[e.ID]; ok {
			continue
		}
		seen[e.ID] = struct{}{}
		deduped = append(deduped, e)
	}
	al.Entries = deduped
	return al, nil
}

// LoadFile reads and parses the allowlist at path. If the file does not
// exist, it returns an empty allowlist — callers do not need to check for
// os.ErrNotExist.
func LoadFile(path string) (*Allowlist, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Allowlist{Version: "1"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("suppress: read %s: %w", path, err)
	}
	return Load(data)
}

// Apply filters findings, removing any whose ID appears in al. It returns
// the retained findings and the count of suppressed findings.
func Apply(findings []model.Finding, al *Allowlist) (retained []model.Finding, suppressed int) {
	if al == nil || len(al.Entries) == 0 {
		return findings, 0
	}
	ids := make(map[string]struct{}, len(al.Entries))
	for _, e := range al.Entries {
		ids[e.ID] = struct{}{}
	}
	for _, f := range findings {
		if _, ok := ids[f.ID]; ok {
			suppressed++
			continue
		}
		retained = append(retained, f)
	}
	return retained, suppressed
}

// FromFindings builds an Allowlist from a slice of findings, recording
// addedBy and note on each entry. Callers pass the current UTC time in
// addedAt; if zero it defaults to now.
func FromFindings(findings []model.Finding, addedBy, note string) *Allowlist {
	al := &Allowlist{Version: "1"}
	now := time.Now().UTC().Format(time.RFC3339)
	seen := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		if _, ok := seen[f.ID]; ok {
			continue
		}
		seen[f.ID] = struct{}{}
		e := Entry{
			ID:      f.ID,
			AddedAt: now,
			AddedBy: addedBy,
			Note:    note,
		}
		al.Entries = append(al.Entries, e)
	}
	return al
}

// Merge combines existing with incoming entries. Existing entries take
// precedence: any ID already present in existing is not overwritten.
// The returned allowlist carries existing.Description if non-empty,
// otherwise incoming.Description.
func Merge(existing, incoming *Allowlist) *Allowlist {
	if existing == nil {
		existing = &Allowlist{Version: "1"}
	}
	if incoming == nil {
		return existing
	}
	out := &Allowlist{Version: "1"}
	out.Description = existing.Description
	if out.Description == "" {
		out.Description = incoming.Description
	}

	seen := make(map[string]struct{}, len(existing.Entries)+len(incoming.Entries))
	for _, e := range existing.Entries {
		seen[e.ID] = struct{}{}
		out.Entries = append(out.Entries, e)
	}
	for _, e := range incoming.Entries {
		if _, ok := seen[e.ID]; ok {
			continue
		}
		seen[e.ID] = struct{}{}
		out.Entries = append(out.Entries, e)
	}
	return out
}

// Marshal serializes the allowlist to YAML. The output is deterministic
// for the same input.
func Marshal(al *Allowlist) ([]byte, error) {
	if al == nil {
		al = &Allowlist{Version: "1"}
	}
	data, err := yaml.Marshal(al)
	if err != nil {
		return nil, fmt.Errorf("suppress: marshal allowlist: %w", err)
	}
	return data, nil
}

// WriteFile serializes al and writes it to path atomically (write to
// path+".tmp", then rename).
func WriteFile(path string, al *Allowlist) error {
	data, err := Marshal(al)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("suppress: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("suppress: rename %s → %s: %w", tmp, path, err)
	}
	return nil
}
