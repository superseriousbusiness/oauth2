package models

import (
	"net/http"
	"time"
)

// TokenGenerateRequest provides token generation parameters.
type TokenGenerateRequest struct {
	ClientID            string
	ClientSecret        string
	UserID              string
	RedirectURI         string
	Scope               string
	Code                string
	CodeChallenge       string
	CodeChallengeMethod CodeChallengeMethod
	Refresh             string
	CodeVerifier        string
	AccessTokenExp      time.Duration
	Request             *http.Request
}
