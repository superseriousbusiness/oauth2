package token

import (
	"context"
	"time"

	"github.com/superseriousbusiness/oauth2/pkg/errors"
	"github.com/superseriousbusiness/oauth2/pkg/generate"
	"github.com/superseriousbusiness/oauth2/pkg/models"
	"github.com/superseriousbusiness/oauth2/pkg/store"
)

// Manager authorization management interface
type Manager interface {
	// get the client information
	GetClient(ctx context.Context, clientID string) (cli models.Client, err error)
	// generate the authorization token(code)
	GenerateAuthToken(ctx context.Context, rt models.ResponseType, tgr *models.TokenGenerateRequest) (authToken models.Token, err error)
	// generate the access token
	GenerateAccessToken(ctx context.Context, rt models.GrantType, tgr *models.TokenGenerateRequest) (accessToken models.Token, err error)
	// refreshing an access token
	RefreshAccessToken(ctx context.Context, tgr *models.TokenGenerateRequest) (accessToken models.Token, err error)
	// use the access token to delete the token information
	RemoveAccessToken(ctx context.Context, access string) (err error)
	// use the refresh token to delete the token information
	RemoveRefreshToken(ctx context.Context, refresh string) (err error)
	// according to the access token for corresponding token information
	LoadAccessToken(ctx context.Context, access string) (ti models.Token, err error)
	// according to the refresh token for corresponding token information
	LoadRefreshToken(ctx context.Context, refresh string) (ti models.Token, err error)

	// set authorization code expirty time
	SetAuthorizeCodeExp(exp time.Duration)
	// set authorization code token configuration
	SetAuthorizeCodeTokenCfg(cfg *Config)
	// set implicit token configuration
	SetImplicitTokenCfg(cfg *Config)
	// set password token configuration
	SetPasswordTokenCfg(cfg *Config)
	// set client token configuration
	SetClientTokenCfg(cfg *Config)
	// set refresh token configuration
	SetRefreshTokenCfg(cfg *RefreshConfig)
	// set the URI validation handler
	SetValidateURIHandler(handler generate.RedirectValidationHandler)
	// set the token storage for the manager
	MapTokenStorage(store store.TokenStore)
	// set the client storage for the manager
	MapClientStorage(store store.ClientStore)
	// set the authorization token generator for the manager
	MapAuthorizeGenerate(authorizeGenerate generate.AuthorizationTokenGenerator)
	// set the access token generator for the manager
	MapAccessGenerate(accessGenerate generate.AccessTokenGenerator)
}

// DefaultManager returns a default token manager.
func DefaultManager() Manager {
	m := &manager{
		gtcfg:       make(map[models.GrantType]*Config),
		validateURI: generate.DefaultRedirectValidation,
	}

	// default implementation
	m.MapAuthorizeGenerate(generate.DefaultAuthorizationTokenGenerator())
	m.MapAccessGenerate(generate.DefaultAccessTokenGenerator())
	return m
}

// Manager provide authorization management
type manager struct {
	codeExp           time.Duration
	gtcfg             map[models.GrantType]*Config
	rcfg              *RefreshConfig
	validateURI       generate.RedirectValidationHandler
	authorizeGenerate generate.AuthorizationTokenGenerator
	accessGenerate    generate.AccessTokenGenerator
	tokenStore        store.TokenStore
	clientStore       store.ClientStore
}

// get grant type config
func (m *manager) grantConfig(gt models.GrantType) *Config {
	if c, ok := m.gtcfg[gt]; ok && c != nil {
		return c
	}
	switch gt {
	case models.GrantTypeAuthorizationCode:
		return DefaultAuthorizationCodeTokenCfg()
	case models.GrantTypeImplicit:
		return DefaultImplicitTokenCfg()
	case models.GrantTypePassword:
		return DefaultPasswordTokenCfg()
	case models.GrantTypeClientCredentials:
		return DefaultClientTokenCfg()
	}
	return &Config{}
}

// SetAuthorizeCodeExp set the authorization code expiration time
func (m *manager) SetAuthorizeCodeExp(exp time.Duration) {
	m.codeExp = exp
}

// SetAuthorizeCodeTokenCfg set the authorization code grant token config
func (m *manager) SetAuthorizeCodeTokenCfg(cfg *Config) {
	m.gtcfg[models.GrantTypeAuthorizationCode] = cfg
}

// SetImplicitTokenCfg set the implicit grant token config
func (m *manager) SetImplicitTokenCfg(cfg *Config) {
	m.gtcfg[models.GrantTypeImplicit] = cfg
}

// SetPasswordTokenCfg set the password grant token config
func (m *manager) SetPasswordTokenCfg(cfg *Config) {
	m.gtcfg[models.GrantTypePassword] = cfg
}

// SetClientTokenCfg set the client grant token config
func (m *manager) SetClientTokenCfg(cfg *Config) {
	m.gtcfg[models.GrantTypeClientCredentials] = cfg
}

// SetRefreshTokenCfg set the refreshing token config
func (m *manager) SetRefreshTokenCfg(cfg *RefreshConfig) {
	m.rcfg = cfg
}

// SetValidateURIHandler set the validates that RedirectURI is contained in baseURI
func (m *manager) SetValidateURIHandler(handler generate.RedirectValidationHandler) {
	m.validateURI = handler
}

// MapAuthorizeGenerate mapping the authorize code generate interface
func (m *manager) MapAuthorizeGenerate(authorizeGenerate generate.AuthorizationTokenGenerator) {
	m.authorizeGenerate = authorizeGenerate
}

// MapAccessGenerate mapping the access token generate interface
func (m *manager) MapAccessGenerate(accessGenerate generate.AccessTokenGenerator) {
	m.accessGenerate = accessGenerate
}

// MapClientStorage mapping the client store interface
func (m *manager) MapClientStorage(clientStore store.ClientStore) {
	m.clientStore = clientStore
}

// MapTokenStorage mapping the token store interface
func (m *manager) MapTokenStorage(tokenStore store.TokenStore) {
	m.tokenStore = tokenStore
}

// GetClient get the client information
func (m *manager) GetClient(ctx context.Context, clientID string) (cli models.Client, err error) {
	cli, err = m.clientStore.GetByID(ctx, clientID)
	if err != nil {
		return
	} else if cli == nil {
		err = errors.ErrInvalidClient
	}
	return
}

// GenerateAuthToken generate the authorization token(code)
func (m *manager) GenerateAuthToken(ctx context.Context, rt models.ResponseType, tgr *models.TokenGenerateRequest) (models.Token, error) {
	cli, err := m.GetClient(ctx, tgr.ClientID)
	if err != nil {
		return nil, err
	} else if tgr.RedirectURI != "" {
		if err := m.validateURI(cli.GetDomain(), tgr.RedirectURI); err != nil {
			return nil, err
		}
	}

	ti := models.NewToken()
	ti.SetClientID(tgr.ClientID)
	ti.SetUserID(tgr.UserID)
	ti.SetRedirectURI(tgr.RedirectURI)
	ti.SetScope(tgr.Scope)

	createAt := time.Now()
	td := &generate.Parameters{
		Client:    cli,
		UserID:    tgr.UserID,
		CreateAt:  createAt,
		TokenInfo: ti,
		Request:   tgr.Request,
	}
	switch rt {
	case models.ResponseTypeCode:
		codeExp := m.codeExp
		if codeExp == 0 {
			codeExp = defaultCodeExp
		}
		ti.SetCodeCreateAt(createAt)
		ti.SetCodeExpiresIn(codeExp)
		if exp := tgr.AccessTokenExp; exp > 0 {
			ti.SetAccessExpiresIn(exp)
		}
		if tgr.CodeChallenge != "" {
			ti.SetCodeChallenge(tgr.CodeChallenge)
			ti.SetCodeChallengeMethod(tgr.CodeChallengeMethod)
		}

		tv, err := m.authorizeGenerate.Token(ctx, td)
		if err != nil {
			return nil, err
		}
		ti.SetCode(tv)
	case models.ResponseTypeToken:
		// set access token expires
		icfg := m.grantConfig(models.GrantTypeImplicit)
		aexp := icfg.AccessTokenExp
		if exp := tgr.AccessTokenExp; exp > 0 {
			aexp = exp
		}
		ti.SetAccessCreateAt(createAt)
		ti.SetAccessExpiresIn(aexp)

		if icfg.GenerateRefresh {
			ti.SetRefreshCreateAt(createAt)
			ti.SetRefreshExpiresIn(icfg.RefreshTokenExp)
		}

		tv, rv, err := m.accessGenerate.Token(ctx, td, icfg.GenerateRefresh)
		if err != nil {
			return nil, err
		}
		ti.SetAccess(tv)

		if rv != "" {
			ti.SetRefresh(rv)
		}
	}

	err = m.tokenStore.Store(ctx, ti)
	if err != nil {
		return nil, err
	}
	return ti, nil
}

// get authorization code data
func (m *manager) getAuthorizationCode(ctx context.Context, code string) (models.Token, error) {
	ti, err := m.tokenStore.GetByCode(ctx, code)
	if err != nil {
		return nil, err
	} else if ti == nil || ti.GetCode() != code || ti.GetCodeCreateAt().Add(ti.GetCodeExpiresIn()).Before(time.Now()) {
		return nil, errors.ErrInvalidAuthorizeCode
	}
	return ti, nil
}

// delete authorization code data
func (m *manager) delAuthorizationCode(ctx context.Context, code string) error {
	return m.tokenStore.RemoveByCode(ctx, code)
}

// get and delete authorization code data
func (m *manager) getAndDelAuthorizationCode(ctx context.Context, tgr *models.TokenGenerateRequest) (models.Token, error) {
	code := tgr.Code
	ti, err := m.getAuthorizationCode(ctx, code)
	if err != nil {
		return nil, err
	} else if ti.GetClientID() != tgr.ClientID {
		return nil, errors.ErrInvalidAuthorizeCode
	} else if codeURI := ti.GetRedirectURI(); codeURI != "" && codeURI != tgr.RedirectURI {
		return nil, errors.ErrInvalidAuthorizeCode
	}

	err = m.delAuthorizationCode(ctx, code)
	if err != nil {
		return nil, err
	}
	return ti, nil
}

func (m *manager) validateCodeChallenge(ti models.Token, ver string) error {
	cc := ti.GetCodeChallenge()
	// early return
	if cc == "" && ver == "" {
		return nil
	}
	if cc == "" {
		return errors.ErrMissingCodeVerifier
	}
	if ver == "" {
		return errors.ErrMissingCodeVerifier
	}
	ccm := ti.GetCodeChallengeMethod()
	if ccm.String() == "" {
		ccm = models.CodeChallengePlain
	}
	if !ccm.Validate(cc, ver) {
		return errors.ErrInvalidCodeChallenge
	}
	return nil
}

// GenerateAccessToken generate the access token
func (m *manager) GenerateAccessToken(ctx context.Context, gt models.GrantType, tgr *models.TokenGenerateRequest) (models.Token, error) {
	cli, err := m.GetClient(ctx, tgr.ClientID)
	if err != nil {
		return nil, err
	}
	if cliPass, ok := cli.(models.ClientPasswordVerifier); ok {
		if !cliPass.VerifyPassword(tgr.ClientSecret) {
			return nil, errors.ErrInvalidClient
		}
	} else if len(cli.GetSecret()) > 0 && tgr.ClientSecret != cli.GetSecret() {
		return nil, errors.ErrInvalidClient
	}
	if tgr.RedirectURI != "" {
		if err := m.validateURI(cli.GetDomain(), tgr.RedirectURI); err != nil {
			return nil, err
		}
	}

	if gt == models.GrantTypeAuthorizationCode {
		ti, err := m.getAndDelAuthorizationCode(ctx, tgr)
		if err != nil {
			return nil, err
		}
		if err := m.validateCodeChallenge(ti, tgr.CodeVerifier); err != nil {
			return nil, err
		}
		tgr.UserID = ti.GetUserID()
		tgr.Scope = ti.GetScope()
		if exp := ti.GetAccessExpiresIn(); exp > 0 {
			tgr.AccessTokenExp = exp
		}
	}

	ti := models.NewToken()
	ti.SetClientID(tgr.ClientID)
	ti.SetUserID(tgr.UserID)
	ti.SetRedirectURI(tgr.RedirectURI)
	ti.SetScope(tgr.Scope)

	createAt := time.Now()
	ti.SetAccessCreateAt(createAt)

	// set access token expires
	gcfg := m.grantConfig(gt)
	aexp := gcfg.AccessTokenExp
	if exp := tgr.AccessTokenExp; exp > 0 {
		aexp = exp
	}
	ti.SetAccessExpiresIn(aexp)
	if gcfg.GenerateRefresh {
		ti.SetRefreshCreateAt(createAt)
		ti.SetRefreshExpiresIn(gcfg.RefreshTokenExp)
	}

	td := &generate.Parameters{
		Client:    cli,
		UserID:    tgr.UserID,
		CreateAt:  createAt,
		TokenInfo: ti,
		Request:   tgr.Request,
	}

	av, rv, err := m.accessGenerate.Token(ctx, td, gcfg.GenerateRefresh)
	if err != nil {
		return nil, err
	}
	ti.SetAccess(av)

	if rv != "" {
		ti.SetRefresh(rv)
	}

	err = m.tokenStore.Store(ctx, ti)
	if err != nil {
		return nil, err
	}

	return ti, nil
}

// RefreshAccessToken refreshing an access token
func (m *manager) RefreshAccessToken(ctx context.Context, tgr *models.TokenGenerateRequest) (models.Token, error) {
	cli, err := m.GetClient(ctx, tgr.ClientID)
	if err != nil {
		return nil, err
	} else if cliPass, ok := cli.(models.ClientPasswordVerifier); ok {
		if !cliPass.VerifyPassword(tgr.ClientSecret) {
			return nil, errors.ErrInvalidClient
		}
	} else if tgr.ClientSecret != cli.GetSecret() {
		return nil, errors.ErrInvalidClient
	}

	ti, err := m.LoadRefreshToken(ctx, tgr.Refresh)
	if err != nil {
		return nil, err
	} else if ti.GetClientID() != tgr.ClientID {
		return nil, errors.ErrInvalidRefreshToken
	}

	oldAccess, oldRefresh := ti.GetAccess(), ti.GetRefresh()

	td := &generate.Parameters{
		Client:    cli,
		UserID:    ti.GetUserID(),
		CreateAt:  time.Now(),
		TokenInfo: ti,
		Request:   tgr.Request,
	}

	rcfg := DefaultRefreshTokenCfg()
	if v := m.rcfg; v != nil {
		rcfg = v
	}

	ti.SetAccessCreateAt(td.CreateAt)
	if v := rcfg.AccessTokenExp; v > 0 {
		ti.SetAccessExpiresIn(v)
	}

	if v := rcfg.RefreshTokenExp; v > 0 {
		ti.SetRefreshExpiresIn(v)
	}

	if rcfg.ResetRefreshTime {
		ti.SetRefreshCreateAt(td.CreateAt)
	}

	if scope := tgr.Scope; scope != "" {
		ti.SetScope(scope)
	}

	tv, rv, err := m.accessGenerate.Token(ctx, td, rcfg.GenerateRefresh)
	if err != nil {
		return nil, err
	}

	ti.SetAccess(tv)
	if rv != "" {
		ti.SetRefresh(rv)
	}

	if err := m.tokenStore.Store(ctx, ti); err != nil {
		return nil, err
	}

	if rcfg.RemoveAccess {
		// remove the old access token
		if err := m.tokenStore.RemoveByAccess(ctx, oldAccess); err != nil {
			return nil, err
		}
	}

	if rcfg.RemoveRefresh && rv != "" {
		// remove the old refresh token
		if err := m.tokenStore.RemoveByRefresh(ctx, oldRefresh); err != nil {
			return nil, err
		}
	}

	if rv == "" {
		ti.SetRefresh("")
		ti.SetRefreshCreateAt(time.Now())
		ti.SetRefreshExpiresIn(0)
	}

	return ti, nil
}

// RemoveAccessToken use the access token to delete the token information
func (m *manager) RemoveAccessToken(ctx context.Context, access string) error {
	if access == "" {
		return errors.ErrInvalidAccessToken
	}
	return m.tokenStore.RemoveByAccess(ctx, access)
}

// RemoveRefreshToken use the refresh token to delete the token information
func (m *manager) RemoveRefreshToken(ctx context.Context, refresh string) error {
	if refresh == "" {
		return errors.ErrInvalidAccessToken
	}
	return m.tokenStore.RemoveByRefresh(ctx, refresh)
}

// LoadAccessToken according to the access token for corresponding token information
func (m *manager) LoadAccessToken(ctx context.Context, access string) (models.Token, error) {
	if access == "" {
		return nil, errors.ErrInvalidAccessToken
	}

	ct := time.Now()
	ti, err := m.tokenStore.GetByAccess(ctx, access)
	if err != nil {
		return nil, err
	} else if ti == nil || ti.GetAccess() != access {
		return nil, errors.ErrInvalidAccessToken
	} else if ti.GetRefresh() != "" && ti.GetRefreshExpiresIn() != 0 &&
		ti.GetRefreshCreateAt().Add(ti.GetRefreshExpiresIn()).Before(ct) {
		return nil, errors.ErrExpiredRefreshToken
	} else if ti.GetAccessExpiresIn() != 0 &&
		ti.GetAccessCreateAt().Add(ti.GetAccessExpiresIn()).Before(ct) {
		return nil, errors.ErrExpiredAccessToken
	}
	return ti, nil
}

// LoadRefreshToken according to the refresh token for corresponding token information
func (m *manager) LoadRefreshToken(ctx context.Context, refresh string) (models.Token, error) {
	if refresh == "" {
		return nil, errors.ErrInvalidRefreshToken
	}

	ti, err := m.tokenStore.GetByRefresh(ctx, refresh)
	if err != nil {
		return nil, err
	} else if ti == nil || ti.GetRefresh() != refresh {
		return nil, errors.ErrInvalidRefreshToken
	} else if ti.GetRefreshExpiresIn() != 0 && // refresh token set to not expire
		ti.GetRefreshCreateAt().Add(ti.GetRefreshExpiresIn()).Before(time.Now()) {
		return nil, errors.ErrExpiredRefreshToken
	}
	return ti, nil
}
