// Package report renders model.RunResult in possession's three v1.0
// output formats: human (default ASCII), json (deterministic
// pretty-printed), and sarif (SARIF 2.1.0 via go-sarif/v3 for GitHub
// code scanning).
//
// All reporters are pure: they consume model.RunResult and write to an
// io.Writer. No reporter performs network I/O or mutates the input.
// The Reporter interface is one method (Render) plus a Name() string
// so the CLI can select by --report value.
package report
