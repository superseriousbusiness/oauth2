package manager

import "time"

// Config authorization configuration parameters
type Config struct {
	// access token expiration time, 0 means it doesn't expire
	AccessTokenExp time.Duration
	// refresh token expiration time, 0 means it doesn't expire
	RefreshTokenExp time.Duration
	// whether to generate the refreshing token
	IsGenerateRefresh bool
}

// RefreshingConfig refreshing token config
type RefreshingConfig struct {
	// access token expiration time, 0 means it doesn't expire
	AccessTokenExp time.Duration
	// refresh token expiration time, 0 means it doesn't expire
	RefreshTokenExp time.Duration
	// whether to generate the refreshing token
	IsGenerateRefresh bool
	// whether to reset the refreshing create time
	IsResetRefreshTime bool
	// whether to remove access token
	IsRemoveAccess bool
	// whether to remove refreshing token
	IsRemoveRefreshing bool
}

var (
	tenMinutes     = time.Minute * 10
	oneHour        = time.Hour * 1
	twoHours       = time.Hour * 2
	threeDays      = time.Hour * 24 * 3
	oneWeek        = time.Hour * 24 * 7
	defaultCodeExp = tenMinutes
)

func DefaultAuthorizeCodeTokenCfg() *Config {
	return &Config{
		AccessTokenExp:    twoHours,
		RefreshTokenExp:   threeDays,
		IsGenerateRefresh: true,
	}
}

func DefaultImplicitTokenCfg() *Config {
	return &Config{
		AccessTokenExp: oneHour,
	}
}

func DefaultPasswordTokenCfg() *Config {
	return &Config{
		AccessTokenExp:    twoHours,
		RefreshTokenExp:   oneWeek,
		IsGenerateRefresh: true,
	}
}

func DefaultClientTokenCfg() *Config {
	return &Config{
		AccessTokenExp: twoHours,
	}
}

func DefaultRefreshTokenCfg() *RefreshingConfig {
	return &RefreshingConfig{
		IsGenerateRefresh:  true,
		IsRemoveAccess:     true,
		IsRemoveRefreshing: true,
	}
}
