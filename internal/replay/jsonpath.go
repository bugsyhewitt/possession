package replay

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// DottedPath evaluates a minimal dotted-path selector against a decoded JSON
// document (map[string]any / []any / scalar) and returns the value at that
// path or an error.
//
// Grammar (D13):
//
//	path     = "$" segment*
//	segment  = "." name | "[" index "]"
//	name     = [A-Za-z0-9_-]+
//	index    = digits
//
// No wildcards, no filters, no recursive descent — keep the surface area
// small. The hostile case is silently returning the wrong value, which a
// permissive parser invites; we are strict on purpose.
func DottedPath(expr string, doc any) (any, error) {
	if expr == "" {
		return nil, errors.New("jsonpath: empty expression")
	}
	if !strings.HasPrefix(expr, "$") {
		return nil, fmt.Errorf("jsonpath: expression must start with $: %q", expr)
	}
	steps, err := tokenizePath(expr[1:])
	if err != nil {
		return nil, err
	}
	cur := doc
	for _, s := range steps {
		switch s.kind {
		case stepKey:
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("jsonpath: cannot descend into %T at .%s", cur, s.key)
			}
			v, ok := m[s.key]
			if !ok {
				return nil, fmt.Errorf("jsonpath: missing key %q", s.key)
			}
			cur = v
		case stepIndex:
			a, ok := cur.([]any)
			if !ok {
				return nil, fmt.Errorf("jsonpath: cannot index %T at [%d]", cur, s.idx)
			}
			if s.idx < 0 || s.idx >= len(a) {
				return nil, fmt.Errorf("jsonpath: index %d out of range [0,%d)", s.idx, len(a))
			}
			cur = a[s.idx]
		}
	}
	return cur, nil
}

type stepKind int

const (
	stepKey stepKind = iota
	stepIndex
)

type pathStep struct {
	kind stepKind
	key  string
	idx  int
}

func tokenizePath(s string) ([]pathStep, error) {
	out := make([]pathStep, 0, 4)
	i := 0
	for i < len(s) {
		switch s[i] {
		case '.':
			i++
			start := i
			for i < len(s) && s[i] != '.' && s[i] != '[' {
				i++
			}
			if start == i {
				return nil, fmt.Errorf("jsonpath: empty key at position %d", start)
			}
			out = append(out, pathStep{kind: stepKey, key: s[start:i]})
		case '[':
			j := strings.IndexByte(s[i:], ']')
			if j < 0 {
				return nil, errors.New("jsonpath: unterminated [")
			}
			body := s[i+1 : i+j]
			idx, err := strconv.Atoi(body)
			if err != nil {
				return nil, fmt.Errorf("jsonpath: invalid index %q", body)
			}
			out = append(out, pathStep{kind: stepIndex, idx: idx})
			i += j + 1
		default:
			return nil, fmt.Errorf("jsonpath: unexpected %q at position %d", s[i], i)
		}
	}
	return out, nil
}
