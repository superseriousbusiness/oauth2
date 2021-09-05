package token

import "time"

var (
	tenMinutes     = time.Minute * 10
	oneHour        = time.Hour * 1
	twoHours       = time.Hour * 2
	threeDays      = time.Hour * 24 * 3
	oneWeek        = time.Hour * 24 * 7
	defaultCodeExp = tenMinutes
)

// Config contains authorization token generation config.
type Config struct {
	// Access token expiration time.
	// If nil, token will not expire.
	AccessTokenExp time.Duration
	// Refresh token expiration time.
	// If nil, token will not expire.
	RefreshTokenExp time.Duration
	// Generate a refresh token.
	GenerateRefresh bool
}

// RefreshConfig contains refresh token generation config.
type RefreshConfig struct {
	// Access token expiration time.
	// If nil, token will not expire.
	AccessTokenExp time.Duration
	// Refresh token expiration time.
	// If nil, token will not expire.
	RefreshTokenExp time.Duration
	// Generate a refresh token.
	GenerateRefresh bool
	// Reset refresh token create time on generation of a new token.
	ResetRefreshTime bool
	// Remove existing access token when doing a refresh.
	RemoveAccess bool
	// Remove existing refresh token when doing a refresh.
	RemoveRefresh bool
}

// DefaultAuthorizationCodeTokenCfg returns a *Config with the following settings:
//
//   AccessTokenExp:  twoHours
//   RefreshTokenExp: threeDays
//   GenerateRefresh: true
func DefaultAuthorizationCodeTokenCfg() *Config {
	return &Config{
		AccessTokenExp:  twoHours,
		RefreshTokenExp: threeDays,
		GenerateRefresh: true,
	}
}

// DefaultImplicitTokenCfg returns a *Config with the following settings:
//
//   AccessTokenExp:  oneHour
func DefaultImplicitTokenCfg() *Config {
	return &Config{
		AccessTokenExp: oneHour,
	}
}

// DefaultPasswordTokenCfg returns a *Config with the following settings:
//
//   AccessTokenExp:  twoHours
//   RefreshTokenExp: oneWeek
//   GenerateRefresh: true
func DefaultPasswordTokenCfg() *Config {
	return &Config{
		AccessTokenExp:  twoHours,
		RefreshTokenExp: oneWeek,
		GenerateRefresh: true,
	}
}

// DefaultClientTokenCfg returns a *Config with the following settings:
//
//   AccessTokenExp: twoHours
func DefaultClientTokenCfg() *Config {
	return &Config{
		AccessTokenExp: twoHours,
	}
}

// DefaultRefreshTokenCfg returns a *RefreshConfig with the following settings:
//
//   GenerateRefresh: true
//   RemoveAccess: true
//   RemoveRefresh: true
func DefaultRefreshTokenCfg() *RefreshConfig {
	return &RefreshConfig{
		GenerateRefresh: true,
		RemoveAccess:    true,
		RemoveRefresh:   true,
	}
}
