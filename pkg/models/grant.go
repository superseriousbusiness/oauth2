package models

// GrantType represents an OAuth2 grant type: https://oauth.net/2/grant-types/
type GrantType string

const (
	// GrantTypeAuthorizationCode https://oauth.net/2/grant-types/authorization-code/
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	// GrantTypeClientCredentials https://oauth.net/2/grant-types/client-credentials/
	GrantTypeClientCredentials GrantType = "client_credentials"
	// GrantTypeRefreshToken https://oauth.net/2/grant-types/refresh-token/
	GrantTypeRefreshToken GrantType = "refresh_token"
	// GrantTypeImplicit LEGACY -- NOT RECOMMENDED https://oauth.net/2/grant-types/implicit/
	GrantTypeImplicit GrantType = "__implicit"
	// GrantTypePassword LEGACY -- NOT RECOMMENDED https://oauth.net/2/grant-types/password/
	GrantTypePassword GrantType = "password"
)

func (gt GrantType) String() string {
	if gt == GrantTypeAuthorizationCode ||
		gt == GrantTypePassword ||
		gt == GrantTypeClientCredentials ||
		gt == GrantTypeRefreshToken {
		return string(gt)
	}
	return ""
}
