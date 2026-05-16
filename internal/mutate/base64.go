package mutate

import "encoding/base64"

// base64Std is a tiny indirection so basic-auth encoding stays in one place.
func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
