package models

import (
	"time"
)

// Token models an OAuth2 token.
type Token interface {
	GetClientID() string
	SetClientID(string)
	GetUserID() string
	SetUserID(string)
	GetRedirectURI() string
	SetRedirectURI(string)
	GetScope() string
	SetScope(string)

	GetCode() string
	SetCode(string)
	GetCodeCreateAt() time.Time
	SetCodeCreateAt(time.Time)
	GetCodeExpiresIn() time.Duration
	SetCodeExpiresIn(time.Duration)
	GetCodeChallenge() string
	SetCodeChallenge(string)
	GetCodeChallengeMethod() CodeChallengeMethod
	SetCodeChallengeMethod(CodeChallengeMethod)

	GetAccess() string
	SetAccess(string)
	GetAccessCreateAt() time.Time
	SetAccessCreateAt(time.Time)
	GetAccessExpiresIn() time.Duration
	SetAccessExpiresIn(time.Duration)

	GetRefresh() string
	SetRefresh(string)
	GetRefreshCreateAt() time.Time
	SetRefreshCreateAt(time.Time)
	GetRefreshExpiresIn() time.Duration
	SetRefreshExpiresIn(time.Duration)
}

// NewToken returns a new token that can be serialized to JSON.
func NewToken() Token {
	return &SerializableToken{}
}

// SerializableToken models a token that can be serialized to JSON.
type SerializableToken struct {
	ClientID            string        `json:"ClientID,omitempty"`
	UserID              string        `json:"UserID,omitempty"`
	RedirectURI         string        `json:"RedirectURI,omitempty"`
	Scope               string        `json:"Scope,omitempty"`
	Code                string        `json:"Code,omitempty"`
	CodeChallenge       string        `json:"CodeChallenge,omitempty"`
	CodeChallengeMethod string        `json:"CodeChallengeMethod,omitempty"`
	CodeCreateAt        time.Time     `json:"CodeCreateAt,omitempty"`
	CodeExpiresIn       time.Duration `json:"CodeExpiresIn,omitempty"`
	Access              string        `json:"Access,omitempty"`
	AccessCreateAt      time.Time     `json:"AccessCreateAt,omitempty"`
	AccessExpiresIn     time.Duration `json:"AccessExpiresIn,omitempty"`
	Refresh             string        `json:"Refresh,omitempty"`
	RefreshCreateAt     time.Time     `json:"RefreshCreateAt,omitempty"`
	RefreshExpiresIn    time.Duration `json:"RefreshExpiresIn,omitempty"`
}

// New create to token model instance
func (t *SerializableToken) New() Token {
	return NewToken()
}

// GetClientID the client id
func (t *SerializableToken) GetClientID() string {
	return t.ClientID
}

// SetClientID the client id
func (t *SerializableToken) SetClientID(clientID string) {
	t.ClientID = clientID
}

// GetUserID the user id
func (t *SerializableToken) GetUserID() string {
	return t.UserID
}

// SetUserID the user id
func (t *SerializableToken) SetUserID(userID string) {
	t.UserID = userID
}

// GetRedirectURI redirect URI
func (t *SerializableToken) GetRedirectURI() string {
	return t.RedirectURI
}

// SetRedirectURI redirect URI
func (t *SerializableToken) SetRedirectURI(redirectURI string) {
	t.RedirectURI = redirectURI
}

// GetScope get scope of authorization
func (t *SerializableToken) GetScope() string {
	return t.Scope
}

// SetScope get scope of authorization
func (t *SerializableToken) SetScope(scope string) {
	t.Scope = scope
}

// GetCode authorization code
func (t *SerializableToken) GetCode() string {
	return t.Code
}

// SetCode authorization code
func (t *SerializableToken) SetCode(code string) {
	t.Code = code
}

// GetCodeCreateAt create Time
func (t *SerializableToken) GetCodeCreateAt() time.Time {
	return t.CodeCreateAt
}

// SetCodeCreateAt create Time
func (t *SerializableToken) SetCodeCreateAt(createAt time.Time) {
	t.CodeCreateAt = createAt
}

// GetCodeExpiresIn the lifetime in seconds of the authorization code
func (t *SerializableToken) GetCodeExpiresIn() time.Duration {
	return t.CodeExpiresIn
}

// SetCodeExpiresIn the lifetime in seconds of the authorization code
func (t *SerializableToken) SetCodeExpiresIn(exp time.Duration) {
	t.CodeExpiresIn = exp
}

// GetCodeChallenge challenge code
func (t *SerializableToken) GetCodeChallenge() string {
	return t.CodeChallenge
}

// SetCodeChallenge challenge code
func (t *SerializableToken) SetCodeChallenge(code string) {
	t.CodeChallenge = code
}

// GetCodeChallengeMethod challenge method
func (t *SerializableToken) GetCodeChallengeMethod() CodeChallengeMethod {
	return CodeChallengeMethod(t.CodeChallengeMethod)
}

// SetCodeChallengeMethod challenge method
func (t *SerializableToken) SetCodeChallengeMethod(method CodeChallengeMethod) {
	t.CodeChallengeMethod = string(method)
}

// GetAccess access Token
func (t *SerializableToken) GetAccess() string {
	return t.Access
}

// SetAccess access Token
func (t *SerializableToken) SetAccess(access string) {
	t.Access = access
}

// GetAccessCreateAt create Time
func (t *SerializableToken) GetAccessCreateAt() time.Time {
	return t.AccessCreateAt
}

// SetAccessCreateAt create Time
func (t *SerializableToken) SetAccessCreateAt(createAt time.Time) {
	t.AccessCreateAt = createAt
}

// GetAccessExpiresIn the lifetime in seconds of the access token
func (t *SerializableToken) GetAccessExpiresIn() time.Duration {
	return t.AccessExpiresIn
}

// SetAccessExpiresIn the lifetime in seconds of the access token
func (t *SerializableToken) SetAccessExpiresIn(exp time.Duration) {
	t.AccessExpiresIn = exp
}

// GetRefresh refresh Token
func (t *SerializableToken) GetRefresh() string {
	return t.Refresh
}

// SetRefresh refresh Token
func (t *SerializableToken) SetRefresh(refresh string) {
	t.Refresh = refresh
}

// GetRefreshCreateAt create Time
func (t *SerializableToken) GetRefreshCreateAt() time.Time {
	return t.RefreshCreateAt
}

// SetRefreshCreateAt create Time
func (t *SerializableToken) SetRefreshCreateAt(createAt time.Time) {
	t.RefreshCreateAt = createAt
}

// GetRefreshExpiresIn the lifetime in seconds of the refresh token
func (t *SerializableToken) GetRefreshExpiresIn() time.Duration {
	return t.RefreshExpiresIn
}

// SetRefreshExpiresIn the lifetime in seconds of the refresh token
func (t *SerializableToken) SetRefreshExpiresIn(exp time.Duration) {
	t.RefreshExpiresIn = exp
}
