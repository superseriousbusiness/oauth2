package util

import (
	"encoding/base64"
	"strings"
)

var b64 *base64.Encoding

func init() {
	b64 = base64.URLEncoding.WithPadding(base64.NoPadding)
}

// B64Encode encodes a given string without padding, then converts it to uppercase.
func B64Encode(in string) string {
	enc := b64.EncodeToString([]byte(in))
	return strings.ToUpper(enc)
}
