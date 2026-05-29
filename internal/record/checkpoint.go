package record

// checkpoint.go adds crash-safe, incremental persistence on top of the record
// package so a scan that is interrupted (Ctrl-C, network drop, quota wall, host
// reboot) can resume without re-firing the variants it already completed
// (ROADMAP v1.1 "resume on interrupt").
//
// Where a Recording is written once at the end of a run, a Checkpoint is
// appended to continuously *during* the run — one JSON object per completed
// response, one per line. Append-only JSON Lines is the right shape for this:
//
//   - A write is a single short append; no full-file rewrite, so the cost per
//     response is negligible even for a 10k-variant plan.
//   - A crash mid-write can at worst leave a torn final line. Load skips any
//     line that does not parse, so a torn tail never poisons the resume — the
//     affected variant is simply re-fired.
//   - Each record carries its VariantID, so resume matches by ID exactly like
//     --replay does, independent of plan order.
//
// On resume the scan loads the checkpoint, treats every VariantID present as
// already-done, fires only the missing variants live (attaching the same
// checkpoint so the new responses are persisted too), and merges both sets back
// into plan order before detection. A completed scan and a resumed-then
// completed scan therefore feed detection identical inputs.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/bugsyhewitt/possession/internal/model"
)

// CheckpointFilename is the canonical JSON Lines file written inside the
// --resume directory. Distinct from the --record Filename so a single directory
// can (in principle) hold both without collision.
const CheckpointFilename = "checkpoint.jsonl"

// checkpointLine is the on-disk shape of one persisted response. Baseline marks
// whether the response belongs to the owner-baseline plan or the variant plan,
// so resume can route it back to the correct slice.
type checkpointLine struct {
	Baseline bool           `json:"baseline"`
	Response model.Response `json:"response"`
}

// Checkpoint is an append-only, concurrency-safe writer over the JSON Lines
// checkpoint file. The replay engine calls Record from many goroutines as
// responses complete; the mutex serialises the appends so lines never
// interleave. Each append is flushed immediately so an abrupt termination keeps
// everything written up to the last completed response.
type Checkpoint struct {
	mu sync.Mutex
	f  *os.File
	w  *bufio.Writer
}

// OpenCheckpoint opens (creating dir if needed) the checkpoint file for append.
// Existing content is preserved — a resumed run keeps adding to the same file.
func OpenCheckpoint(dir string) (*Checkpoint, error) {
	if dir == "" {
		return nil, fmt.Errorf("record: empty --resume directory")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("record: mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, CheckpointFilename)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) // #nosec G304 - operator-supplied resume dir
	if err != nil {
		return nil, fmt.Errorf("record: open checkpoint %s: %w", path, err)
	}
	return &Checkpoint{f: f, w: bufio.NewWriter(f)}, nil
}

// Record persists one completed response. baseline routes it to the baseline or
// variant set on reload. Responses with an empty VariantID are skipped (they
// can't be matched back to a plan variant on resume, so persisting them is
// pointless). Each line is flushed so a crash never loses a completed response.
func (c *Checkpoint) Record(resp model.Response, baseline bool) {
	if c == nil || resp.VariantID == "" {
		return
	}
	line, err := json.Marshal(checkpointLine{Baseline: baseline, Response: resp})
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _ = c.w.Write(line)
	_ = c.w.WriteByte('\n')
	_ = c.w.Flush()
}

// Close flushes and closes the checkpoint file. Safe to call on a nil receiver.
func (c *Checkpoint) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.w != nil {
		_ = c.w.Flush()
	}
	if c.f != nil {
		return c.f.Close()
	}
	return nil
}

// LoadedCheckpoint holds the responses recovered from a checkpoint file, keyed
// by VariantID and split into baseline vs variant sets.
type LoadedCheckpoint struct {
	Baseline map[string]model.Response
	Variants map[string]model.Response
}

// LoadCheckpoint reads back every well-formed line from dir's checkpoint file.
// A missing file is not an error — it means "nothing to resume" and yields an
// empty (but non-nil) result, so the first run of a --resume scan behaves like
// a normal scan that happens to be checkpointing. Malformed lines (e.g. a torn
// final line from a crash mid-append) are skipped; the affected variants will
// simply be re-fired.
//
// When the same VariantID appears more than once (a resumed run that re-fired a
// variant whose response had not flushed before the crash), the last occurrence
// wins — append order is chronological, so the freshest response is kept.
func LoadCheckpoint(dir string) (*LoadedCheckpoint, error) {
	out := &LoadedCheckpoint{
		Baseline: map[string]model.Response{},
		Variants: map[string]model.Response{},
	}
	if dir == "" {
		return nil, fmt.Errorf("record: empty --resume directory")
	}
	path := filepath.Join(dir, CheckpointFilename)
	f, err := os.Open(path) // #nosec G304 - operator-supplied resume dir
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil // nothing to resume yet
		}
		return nil, fmt.Errorf("record: open checkpoint %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Allow long lines (large response bodies) up to the record body cap.
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var cl checkpointLine
		if err := json.Unmarshal(raw, &cl); err != nil {
			continue // torn or partial line — skip, the variant gets re-fired
		}
		if cl.Response.VariantID == "" {
			continue
		}
		if cl.Baseline {
			out.Baseline[cl.Response.VariantID] = cl.Response
		} else {
			out.Variants[cl.Response.VariantID] = cl.Response
		}
	}
	// A scanner error (other than a torn last line, which surfaces as EOF) means
	// the file is unreadable beyond what we parsed; surface it so the operator
	// knows the resume is partial rather than silently dropping work.
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("record: read checkpoint %s: %w", path, err)
	}
	return out, nil
}

// Counts reports how many baseline and variant responses were recovered.
func (l *LoadedCheckpoint) Counts() (baseline, variants int) {
	if l == nil {
		return 0, 0
	}
	return len(l.Baseline), len(l.Variants)
}
