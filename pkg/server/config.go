package server

import (
	"net/http"
	"time"

	"github.com/superseriousbusiness/oauth2/pkg/models"
)

// Config configuration parameters
type Config struct {
	TokenType                   string                // token type
	AllowGetAccessRequest       bool                  // to allow GET requests for the token
	AllowedResponseTypes        []models.ResponseType // allow the authorization type
	AllowedGrantTypes           []models.GrantType    // allow the grant type
	AllowedCodeChallengeMethods []models.CodeChallengeMethod
	ForcePKCE                   bool
}

// NewConfig returns a default server configuration.
func NewConfig() *Config {
	return &Config{
		TokenType: "Bearer",
		AllowedResponseTypes: []models.ResponseType{
			models.ResponseTypeCode,
			models.ResponseTypeToken,
		},
		AllowedGrantTypes: []models.GrantType{
			models.GrantTypeAuthorizationCode,
			models.GrantTypePasswordCredentials,
			models.GrantTypeClientCredentials,
			models.GrantTypeRefreshing,
		},
		AllowedCodeChallengeMethods: []models.CodeChallengeMethod{
			models.CodeChallengePlain,
			models.CodeChallengeS256,
		},
	}
}

// AuthorizeRequest authorization request
type AuthorizeRequest struct {
	ResponseType        models.ResponseType
	ClientID            string
	Scope               string
	RedirectURI         string
	State               string
	UserID              string
	CodeChallenge       string
	CodeChallengeMethod models.CodeChallengeMethod
	AccessTokenExp      time.Duration
	Request             *http.Request
}
