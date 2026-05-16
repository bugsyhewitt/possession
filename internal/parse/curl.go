package parse

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/bugsyhewitt/possession/internal/model"
)

// Curl parses a curl command from r and returns a single CapturedRequest.
//
// Supported flags: -X/--request, -H/--header, -b/--cookie,
// -d/--data/--data-raw/--data-binary, -u/--user (basic auth), --url, and a
// bare URL argument. Backslash line continuations are honored. Unknown
// flags are reported to stderr but do not fail the parse.
//
// Default method is GET; POST is used if any data flag is present and no
// -X was given.
func Curl(r io.Reader) (*model.CapturedRequest, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("curl: read: %w", err)
	}
	return parseCurl(string(data))
}

func parseCurl(input string) (*model.CapturedRequest, error) {
	// Collapse backslash line continuations: "\\\n" → " ".
	input = strings.ReplaceAll(input, "\\\n", " ")
	input = strings.ReplaceAll(input, "\\\r\n", " ")

	tokens, err := tokenize(input)
	if err != nil {
		return nil, fmt.Errorf("curl: tokenize: %w", err)
	}
	if len(tokens) == 0 {
		return nil, errors.New("curl: empty input")
	}
	// Drop the leading "curl" word if present.
	if strings.EqualFold(tokens[0], "curl") {
		tokens = tokens[1:]
	}

	var (
		method       string
		rawURL       string
		headers      = http.Header{}
		cookieHeader string
		bodyParts    []string
		basicUser    string
		basicPass    string
	)

	takeValue := func(i int, flag string) (string, int, error) {
		if i+1 >= len(tokens) {
			return "", i, fmt.Errorf("flag %s requires a value", flag)
		}
		return tokens[i+1], i + 1, nil
	}

	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		switch {
		case t == "-X" || t == "--request":
			v, ni, err := takeValue(i, t)
			if err != nil {
				return nil, err
			}
			method = strings.ToUpper(v)
			i = ni
		case t == "-H" || t == "--header":
			v, ni, err := takeValue(i, t)
			if err != nil {
				return nil, err
			}
			if name, val, ok := splitHeader(v); ok {
				headers.Add(name, val)
			}
			i = ni
		case t == "-b" || t == "--cookie":
			v, ni, err := takeValue(i, t)
			if err != nil {
				return nil, err
			}
			if cookieHeader == "" {
				cookieHeader = v
			} else {
				cookieHeader += "; " + v
			}
			i = ni
		case t == "-d" || t == "--data" || t == "--data-raw" || t == "--data-binary":
			v, ni, err := takeValue(i, t)
			if err != nil {
				return nil, err
			}
			bodyParts = append(bodyParts, v)
			i = ni
		case t == "-u" || t == "--user":
			v, ni, err := takeValue(i, t)
			if err != nil {
				return nil, err
			}
			basicUser, basicPass = splitUserPass(v)
			i = ni
		case t == "--url":
			v, ni, err := takeValue(i, t)
			if err != nil {
				return nil, err
			}
			rawURL = v
			i = ni
		case strings.HasPrefix(t, "-"):
			// Unknown flag: warn, don't fail. Some flags take values; we
			// cannot know without a full curl flag table, so we leave the
			// following token to be reinterpreted as a possible URL or
			// flag. This mirrors lenient HAR/curl tooling.
			fmt.Fprintf(os.Stderr, "curl: warning: ignoring unknown flag %q\n", t)
		default:
			if rawURL == "" {
				rawURL = t
			}
		}
	}

	if rawURL == "" {
		return nil, errors.New("curl: no URL found")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("curl: parse url: %w", err)
	}

	body := []byte(strings.Join(bodyParts, "&"))
	if method == "" {
		if len(body) > 0 {
			method = "POST"
		} else {
			method = "GET"
		}
	}

	// Cookie handling: merge -b values with any cookie headers; expose via
	// the Cookies slice in addition to the Cookie header.
	var cookies []*http.Cookie
	if cookieHeader != "" {
		headers.Set("Cookie", cookieHeader)
	}
	if ch := headers.Get("Cookie"); ch != "" {
		// Use a synthetic request to leverage stdlib cookie parsing.
		req := &http.Request{Header: http.Header{"Cookie": []string{ch}}}
		cookies = req.Cookies()
	}

	if basicUser != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(basicUser + ":" + basicPass))
		headers.Set("Authorization", "Basic "+auth)
	}

	contentType := headers.Get("Content-Type")

	req := &model.CapturedRequest{
		Method:      method,
		URL:         u,
		Headers:     headers,
		Cookies:     cookies,
		Body:        body,
		ContentType: contentType,
		Source:      "curl",
	}
	req.ID = stableCurlID(req)
	return req, nil
}

func splitHeader(h string) (name, value string, ok bool) {
	i := strings.IndexByte(h, ':')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:]), true
}

func splitUserPass(u string) (string, string) {
	i := strings.IndexByte(u, ':')
	if i < 0 {
		return u, ""
	}
	return u[:i], u[i+1:]
}

func stableCurlID(r *model.CapturedRequest) string {
	h := sha1.New()
	h.Write([]byte(r.Method))
	h.Write([]byte{0})
	if r.URL != nil {
		h.Write([]byte(r.URL.String()))
	}
	h.Write([]byte{0})
	h.Write(r.Body)
	return hex.EncodeToString(h.Sum(nil))
}

// tokenize splits a shell-ish curl invocation into tokens, honoring single
// and double quotes. It is intentionally minimal — it does NOT expand
// environment variables, command substitutions, or globs. That is the
// correct behavior for parsing a pasted-in curl snippet.
func tokenize(s string) ([]string, error) {
	var (
		out   []string
		buf   strings.Builder
		inSQ  bool
		inDQ  bool
		esc   bool
		begun bool
	)
	flush := func() {
		if begun {
			out = append(out, buf.String())
			buf.Reset()
			begun = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if esc {
			buf.WriteByte(c)
			begun = true
			esc = false
			continue
		}
		switch {
		case c == '\\' && !inSQ:
			esc = true
		case c == '\'' && !inDQ:
			inSQ = !inSQ
			begun = true
		case c == '"' && !inSQ:
			inDQ = !inDQ
			begun = true
		case (c == ' ' || c == '\t' || c == '\n' || c == '\r') && !inSQ && !inDQ:
			flush()
		default:
			buf.WriteByte(c)
			begun = true
		}
	}
	if inSQ || inDQ {
		return nil, errors.New("unterminated quote")
	}
	flush()
	return out, nil
}
