package models

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// CodeChallengeMethod represents the PCKE method. See https://www.oauth.com/oauth2-servers/pkce/authorization-code-exchange/
type CodeChallengeMethod string

const (
	// CodeChallengePlain PCKE Method
	CodeChallengePlain CodeChallengeMethod = "plain"
	// CodeChallengeS256 PCKE Method
	CodeChallengeS256 CodeChallengeMethod = "S256"
)

func (ccm CodeChallengeMethod) String() string {
	if ccm == CodeChallengePlain ||
		ccm == CodeChallengeS256 {
		return string(ccm)
	}
	return ""
}

// Validate code challenge
func (ccm CodeChallengeMethod) Validate(cc, ver string) bool {
	switch ccm {
	case CodeChallengePlain:
		return cc == ver
	case CodeChallengeS256:
		s256 := sha256.Sum256([]byte(ver))
		// trim padding
		a := strings.TrimRight(base64.URLEncoding.EncodeToString(s256[:]), "=")
		b := strings.TrimRight(cc, "=")
		return a == b
	default:
		return false
	}
}
