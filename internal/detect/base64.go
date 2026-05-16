package detect

import "encoding/base64"

// base64Decode wraps stdlib std-encoding decode so callers stay simple.
func base64Decode(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
