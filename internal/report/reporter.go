package report

import (
	"fmt"
	"io"

	"github.com/bugsyhewitt/possession/internal/model"
)

// Reporter renders a RunResult to a writer. Implementations: HumanReporter,
// JSONReporter, SARIFReporter, MarkdownReporter.
type Reporter interface {
	Name() string
	Render(run *model.RunResult, w io.Writer) error
}

// New returns the reporter whose Name() matches name, with default options.
// The markdown reporter redacts credentials by default; use NewWithOpts to
// override. Unknown names return an error so the CLI can surface a useful
// message.
func New(name string) (Reporter, error) {
	return NewWithOpts(name, ReproOptions{})
}

// NewWithOpts is New with reproduction options. opts currently only affects
// the markdown reporter (credential redaction in per-finding repro blocks);
// other reporters ignore it.
func NewWithOpts(name string, opts ReproOptions) (Reporter, error) {
	switch name {
	case "human", "":
		return HumanReporter{}, nil
	case "json":
		return JSONReporter{}, nil
	case "sarif":
		return SARIFReporter{}, nil
	case "markdown":
		return MarkdownReporter{ReproOpts: opts}, nil
	default:
		return nil, fmt.Errorf("unknown reporter %q (want one of: human, json, sarif, markdown)", name)
	}
}
