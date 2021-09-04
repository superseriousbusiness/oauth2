package models

// GrantType authorization model
type GrantType string

// define authorization model
const (
	GrantTypeAuthorizationCode   GrantType = "authorization_code"
	GrantTypePasswordCredentials GrantType = "password"
	GrantTypeClientCredentials   GrantType = "client_credentials"
	GrantTypeRefreshing          GrantType = "refresh_token"
	GrantTypeImplicit            GrantType = "__implicit"
)

func (gt GrantType) String() string {
	if gt == GrantTypeAuthorizationCode ||
		gt == GrantTypePasswordCredentials ||
		gt == GrantTypeClientCredentials ||
		gt == GrantTypeRefreshing {
		return string(gt)
	}
	return ""
}
