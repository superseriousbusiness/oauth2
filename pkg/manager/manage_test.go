package manager_test

import (
	"context"
	"testing"
	"time"

	"github.com/superseriousbusiness/oauth2/pkg/manager"
	"github.com/superseriousbusiness/oauth2/pkg/models"
	"github.com/superseriousbusiness/oauth2/pkg/store"

	. "github.com/smartystreets/goconvey/convey"
)

func TestManager(t *testing.T) {
	Convey("Manager test", t, func() {
		m := manager.NewDefaultManager()
		ctx := context.Background()

		tokenStorage, err := store.NewMemoryTokenStore()
		if err != nil {
			panic(err)
		}
		m.MapTokenStorage(tokenStorage)

		clientStore := store.NewClientStore()
		err = clientStore.Set(ctx, "1", models.New("1", "11", "http://localhost", ""))
		if err != nil {
			panic(err)
		}
		m.MapClientStorage(clientStore)

		tgr := &models.TokenGenerateRequest{
			ClientID:    "1",
			UserID:      "123456",
			RedirectURI: "http://localhost/oauth2",
			Scope:       "all",
		}

		Convey("GetClient test", func() {
			cli, err := m.GetClient(ctx, "1")
			So(err, ShouldBeNil)
			So(cli.GetSecret(), ShouldEqual, "11")
		})

		Convey("Token test", func() {
			testManager(tgr, m)
		})

		Convey("zero expiration access token test", func() {
			testZeroAccessExpirationManager(tgr, m)
			testCannotRequestZeroExpirationAccessTokens(tgr, m)
		})

		Convey("zero expiration refresh token test", func() {
			testZeroRefreshExpirationManager(tgr, m)
		})
	})
}

func testManager(tgr *models.TokenGenerateRequest, m manager.Manager) {
	ctx := context.Background()
	cti, err := m.GenerateAuthToken(ctx, models.ResponseTypeCode, tgr)
	So(err, ShouldBeNil)

	code := cti.GetCode()
	So(code, ShouldNotBeEmpty)

	atParams := &models.TokenGenerateRequest{
		ClientID:     tgr.ClientID,
		ClientSecret: "11",
		RedirectURI:  tgr.RedirectURI,
		Code:         code,
	}
	ati, err := m.GenerateAccessToken(ctx, models.GrantTypeAuthorizationCode, atParams)
	So(err, ShouldBeNil)

	accessToken, refreshToken := ati.GetAccess(), ati.GetRefresh()
	So(accessToken, ShouldNotBeEmpty)
	So(refreshToken, ShouldNotBeEmpty)

	ainfo, err := m.LoadAccessToken(ctx, accessToken)
	So(err, ShouldBeNil)
	So(ainfo.GetClientID(), ShouldEqual, atParams.ClientID)

	arinfo, err := m.LoadRefreshToken(ctx, accessToken)
	So(err, ShouldNotBeNil)
	So(arinfo, ShouldBeNil)

	rainfo, err := m.LoadAccessToken(ctx, refreshToken)
	So(err, ShouldNotBeNil)
	So(rainfo, ShouldBeNil)

	rinfo, err := m.LoadRefreshToken(ctx, refreshToken)
	So(err, ShouldBeNil)
	So(rinfo.GetClientID(), ShouldEqual, atParams.ClientID)

	atParams.Refresh = refreshToken
	atParams.Scope = "owner"
	rti, err := m.RefreshAccessToken(ctx, atParams)
	So(err, ShouldBeNil)

	refreshAT := rti.GetAccess()
	So(refreshAT, ShouldNotBeEmpty)

	_, err = m.LoadAccessToken(ctx, accessToken)
	So(err, ShouldNotBeNil)

	refreshAInfo, err := m.LoadAccessToken(ctx, refreshAT)
	So(err, ShouldBeNil)
	So(refreshAInfo.GetScope(), ShouldEqual, "owner")

	err = m.RemoveAccessToken(ctx, refreshAT)
	So(err, ShouldBeNil)

	_, err = m.LoadAccessToken(ctx, refreshAT)
	So(err, ShouldNotBeNil)

	err = m.RemoveRefreshToken(ctx, refreshToken)
	So(err, ShouldBeNil)

	_, err = m.LoadRefreshToken(ctx, refreshToken)
	So(err, ShouldNotBeNil)
}

func testZeroAccessExpirationManager(tgr *models.TokenGenerateRequest, m manager.Manager) {
	ctx := context.Background()
	config := manager.Config{
		AccessTokenExp:    0, // Set explicitly as we're testing 0 (no) expiration
		IsGenerateRefresh: true,
	}

	m.SetAuthorizeCodeTokenCfg(&config)

	cti, err := m.GenerateAuthToken(ctx, models.ResponseTypeCode, tgr)
	So(err, ShouldBeNil)

	code := cti.GetCode()
	So(code, ShouldNotBeEmpty)

	atParams := &models.TokenGenerateRequest{
		ClientID:     tgr.ClientID,
		ClientSecret: "11",
		RedirectURI:  tgr.RedirectURI,
		Code:         code,
	}
	ati, err := m.GenerateAccessToken(ctx, models.GrantTypeAuthorizationCode, atParams)
	So(err, ShouldBeNil)

	accessToken, refreshToken := ati.GetAccess(), ati.GetRefresh()
	So(accessToken, ShouldNotBeEmpty)
	So(refreshToken, ShouldNotBeEmpty)

	tokenInfo, err := m.LoadAccessToken(ctx, accessToken)
	So(err, ShouldBeNil)
	So(tokenInfo, ShouldNotBeNil)
	So(tokenInfo.GetAccess(), ShouldEqual, accessToken)
	So(tokenInfo.GetAccessExpiresIn(), ShouldEqual, 0)
}

func testCannotRequestZeroExpirationAccessTokens(tgr *models.TokenGenerateRequest, m manager.Manager) {
	ctx := context.Background()
	config := manager.Config{
		AccessTokenExp: time.Hour * 5,
	}

	m.SetAuthorizeCodeTokenCfg(&config)

	cti, err := m.GenerateAuthToken(ctx, models.ResponseTypeCode, tgr)
	So(err, ShouldBeNil)

	code := cti.GetCode()
	So(code, ShouldNotBeEmpty)

	atParams := &models.TokenGenerateRequest{
		ClientID:       tgr.ClientID,
		ClientSecret:   "11",
		RedirectURI:    tgr.RedirectURI,
		AccessTokenExp: 0, // requesting token without expiration
		Code:           code,
	}
	ati, err := m.GenerateAccessToken(ctx, models.GrantTypeAuthorizationCode, atParams)
	So(err, ShouldBeNil)

	accessToken := ati.GetAccess()
	So(accessToken, ShouldNotBeEmpty)
	So(ati.GetAccessExpiresIn(), ShouldEqual, time.Hour*5)
}

func testZeroRefreshExpirationManager(tgr *models.TokenGenerateRequest, m manager.Manager) {
	ctx := context.Background()
	config := manager.Config{
		RefreshTokenExp:   0, // Set explicitly as we're testing 0 (no) expiration
		IsGenerateRefresh: true,
	}
	m.SetAuthorizeCodeTokenCfg(&config)

	cti, err := m.GenerateAuthToken(ctx, models.ResponseTypeCode, tgr)
	So(err, ShouldBeNil)

	code := cti.GetCode()
	So(code, ShouldNotBeEmpty)

	atParams := &models.TokenGenerateRequest{
		ClientID:       tgr.ClientID,
		ClientSecret:   "11",
		RedirectURI:    tgr.RedirectURI,
		AccessTokenExp: time.Hour,
		Code:           code,
	}
	ati, err := m.GenerateAccessToken(ctx, models.GrantTypeAuthorizationCode, atParams)
	So(err, ShouldBeNil)

	accessToken, refreshToken := ati.GetAccess(), ati.GetRefresh()
	So(accessToken, ShouldNotBeEmpty)
	So(refreshToken, ShouldNotBeEmpty)

	tokenInfo, err := m.LoadRefreshToken(ctx, refreshToken)
	So(err, ShouldBeNil)
	So(tokenInfo, ShouldNotBeNil)
	So(tokenInfo.GetRefresh(), ShouldEqual, refreshToken)
	So(tokenInfo.GetRefreshExpiresIn(), ShouldEqual, 0)

	// LoadAccessToken also checks refresh expiry
	tokenInfo, err = m.LoadAccessToken(ctx, accessToken)
	So(err, ShouldBeNil)
	So(tokenInfo, ShouldNotBeNil)
	So(tokenInfo.GetRefresh(), ShouldEqual, refreshToken)
	So(tokenInfo.GetRefreshExpiresIn(), ShouldEqual, 0)
}
