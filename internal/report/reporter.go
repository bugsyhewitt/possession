package report

import (
	"fmt"
	"io"

	"github.com/bugsyhewitt/possession/internal/model"
)

// Reporter renders a RunResult to a writer. Implementations: HumanReporter,
// JSONReporter, SARIFReporter.
type Reporter interface {
	Name() string
	Render(run *model.RunResult, w io.Writer) error
}

// New returns the reporter whose Name() matches name. Unknown names
// return an error so the CLI can surface a useful message.
func New(name string) (Reporter, error) {
	switch name {
	case "human", "":
		return HumanReporter{}, nil
	case "json":
		return JSONReporter{}, nil
	case "sarif":
		return SARIFReporter{}, nil
	default:
		return nil, fmt.Errorf("unknown reporter %q (want one of: human, json, sarif)", name)
	}
}
