package token_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/superseriousbusiness/oauth2/pkg/models"
	"github.com/superseriousbusiness/oauth2/pkg/store"
	"github.com/superseriousbusiness/oauth2/pkg/token"
)

type ManagerTestSuite struct {
	suite.Suite
	m   token.Manager
	tgr *models.TokenGenerateRequest
}

func (suite *ManagerTestSuite) SetupTest() {
	suite.m = token.DefaultManager()
	ctx := context.Background()

	tokenStorage, err := store.NewMemoryTokenStore()
	if err != nil {
		panic(err)
	}
	suite.m.MapTokenStorage(tokenStorage)

	clientStore := store.InMemClientStore()
	err = clientStore.Set(ctx, "1", models.NewClient("1", "11", "http://localhost", ""))
	if err != nil {
		panic(err)
	}
	suite.m.MapClientStorage(clientStore)

	suite.tgr = &models.TokenGenerateRequest{
		ClientID:    "1",
		UserID:      "123456",
		RedirectURI: "http://localhost/oauth2",
		Scope:       "all",
	}
}

func (suite *ManagerTestSuite) TestManager() {
	ctx := context.Background()
	cti, err := suite.m.GenerateAuthToken(ctx, models.ResponseTypeCode, suite.tgr)
	suite.Nil(err)
	suite.NotNil(cti)
	suite.Len(cti.GetCode(), 48)

	atParams := &models.TokenGenerateRequest{
		ClientID:     suite.tgr.ClientID,
		ClientSecret: "11",
		RedirectURI:  suite.tgr.RedirectURI,
		Code:         cti.GetCode(),
	}
	ati, err := suite.m.GenerateAccessToken(ctx, models.GrantTypeAuthorizationCode, atParams)
	suite.Nil(err)
	suite.NotNil(ati)

	accessToken := ati.GetAccess()
	refreshToken := ati.GetRefresh()
	suite.Len(accessToken, 48)
	suite.Len(refreshToken, 48)

	ainfo, err := suite.m.LoadAccessToken(ctx, accessToken)
	suite.Nil(err)
	suite.Equal(ainfo.GetClientID(), atParams.ClientID)

	arinfo, err := suite.m.LoadRefreshToken(ctx, refreshToken)
	suite.Nil(err)
	suite.NotNil(arinfo)

	rainfo, err := suite.m.LoadAccessToken(ctx, accessToken)
	suite.Nil(err)
	suite.NotNil(rainfo)

	rinfo, err := suite.m.LoadRefreshToken(ctx, refreshToken)
	suite.Nil(err)
	suite.Equal(rinfo.GetClientID(), atParams.ClientID)

	atParams.Refresh = refreshToken
	atParams.Scope = "owner"
	rti, err := suite.m.RefreshAccessToken(ctx, atParams)
	suite.Nil(err)
	suite.NotNil(rti)

	refreshAccessToken := rti.GetAccess()
	suite.NotEmpty(refreshAccessToken)

	_, err = suite.m.LoadAccessToken(ctx, accessToken)
	suite.Error(err)

	refreshAccessTokenInfo, err := suite.m.LoadAccessToken(ctx, refreshAccessToken)
	suite.Nil(err)
	suite.Equal("owner", refreshAccessTokenInfo.GetScope())

	err = suite.m.RemoveAccessToken(ctx, refreshAccessToken)
	suite.Nil(err)

	_, err = suite.m.LoadAccessToken(ctx, refreshAccessToken)
	suite.Error(err)

	err = suite.m.RemoveRefreshToken(ctx, refreshToken)
	suite.Nil(err)

	_, err = suite.m.LoadRefreshToken(ctx, refreshToken)
	suite.Error(err)
}

func (suite *ManagerTestSuite) TestZeroAccessExpirationManager() {
	ctx := context.Background()

	config := &token.Config{
		AccessTokenExp:  0, // Set explicitly as we're testing 0 (no) expiration
		GenerateRefresh: true,
	}

	suite.m.SetAuthorizeCodeTokenCfg(config)

	cti, err := suite.m.GenerateAuthToken(ctx, models.ResponseTypeCode, suite.tgr)
	suite.Nil(err)
	suite.NotNil(cti)
	suite.Len(cti.GetCode(), 48)

	atParams := &models.TokenGenerateRequest{
		ClientID:     suite.tgr.ClientID,
		ClientSecret: "11",
		RedirectURI:  suite.tgr.RedirectURI,
		Code:         cti.GetCode(),
	}
	ati, err := suite.m.GenerateAccessToken(ctx, models.GrantTypeAuthorizationCode, atParams)
	suite.Nil(err)
	suite.NotNil(ati)
	suite.Len(ati.GetAccess(), 48)
	suite.Len(ati.GetRefresh(), 48)

	tokenInfo, err := suite.m.LoadAccessToken(ctx, ati.GetAccess())
	suite.Nil(err)
	suite.NotNil(tokenInfo)
	suite.Equal(tokenInfo.GetAccess(), ati.GetAccess())
	suite.Zero(tokenInfo.GetAccessExpiresIn())
}

func (suite *ManagerTestSuite) TestCannotRequestZeroExpirationAccessTokens() {
	ctx := context.Background()
	config := &token.Config{
		AccessTokenExp: time.Hour * 5,
	}

	suite.m.SetAuthorizeCodeTokenCfg(config)

	cti, err := suite.m.GenerateAuthToken(ctx, models.ResponseTypeCode, suite.tgr)
	suite.Nil(err)

	code := cti.GetCode()
	suite.Len(code, 48)

	atParams := &models.TokenGenerateRequest{
		ClientID:       suite.tgr.ClientID,
		ClientSecret:   "11",
		RedirectURI:    suite.tgr.RedirectURI,
		AccessTokenExp: 0, // requesting token without expiration
		Code:           code,
	}

	ati, err := suite.m.GenerateAccessToken(ctx, models.GrantTypeAuthorizationCode, atParams)
	suite.Nil(err)
	suite.NotNil(ati)

	accessToken := ati.GetAccess()
	suite.Len(accessToken, 48)
	suite.Equal(ati.GetAccessExpiresIn(), time.Hour*5)
}

func (suite *ManagerTestSuite) TestZeroRefreshExpirationManager() {
	ctx := context.Background()
	config := &token.Config{
		RefreshTokenExp: 0, // Set explicitly as we're testing 0 (no) expiration
		GenerateRefresh: true,
	}
	suite.m.SetAuthorizeCodeTokenCfg(config)

	cti, err := suite.m.GenerateAuthToken(ctx, models.ResponseTypeCode, suite.tgr)
	suite.Nil(err)
	suite.NotNil(cti)

	code := cti.GetCode()
	suite.Len(code, 48)

	atParams := &models.TokenGenerateRequest{
		ClientID:       suite.tgr.ClientID,
		ClientSecret:   "11",
		RedirectURI:    suite.tgr.RedirectURI,
		AccessTokenExp: time.Hour,
		Code:           code,
	}
	ati, err := suite.m.GenerateAccessToken(ctx, models.GrantTypeAuthorizationCode, atParams)
	suite.Nil(err)
	suite.NotNil(ati)

	accessToken := ati.GetAccess()
	refreshToken := ati.GetRefresh()
	suite.Len(accessToken, 48)
	suite.Len(refreshToken, 48)

	tokenInfo, err := suite.m.LoadRefreshToken(ctx, refreshToken)
	suite.Nil(err)
	suite.NotNil(tokenInfo)
	suite.Equal(tokenInfo.GetRefresh(), refreshToken)
	suite.Zero(tokenInfo.GetRefreshExpiresIn())

	tokenInfo, err = suite.m.LoadAccessToken(ctx, accessToken)
	suite.Nil(err)
	suite.NotNil(tokenInfo)
	suite.Equal(tokenInfo.GetRefresh(), refreshToken)
	suite.Zero(tokenInfo.GetRefreshExpiresIn())
}

func TestManagerTestSuite(t *testing.T) {
	suite.Run(t, &ManagerTestSuite{})
}
