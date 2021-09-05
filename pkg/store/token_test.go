package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/superseriousbusiness/oauth2/pkg/models"
	"github.com/superseriousbusiness/oauth2/pkg/store"
)

type TokenStoreTestSuite struct {
	StoreTestSuite
	store store.TokenStore
}

func (suite *TokenStoreTestSuite) SetupTest() {
	store, err := store.NewMemoryTokenStore()
	if err != nil {
		panic(err)
	}
	suite.store = store
}

func (suite *TokenStoreTestSuite) TestAuthorizationCodeStore() {
	ctx := context.Background()

	token := models.NewToken()
	token.SetClientID("1")
	token.SetUserID("1_1")
	token.SetRedirectURI("http://localhost/")
	token.SetScope("all")
	token.SetCode("11_11_11")
	token.SetCodeCreateAt(time.Now())
	token.SetCodeExpiresIn(time.Second * 5)

	err := suite.store.Store(ctx, token)
	suite.Nil(err)

	cinfo, err := suite.store.GetByCode(ctx, token.GetCode())
	suite.Nil(err)
	suite.Equal(cinfo.GetUserID(), token.GetUserID())

	err = suite.store.RemoveByCode(ctx, token.GetCode())
	suite.Nil(err)

	cinfo, err = suite.store.GetByCode(ctx, token.GetCode())
	suite.Nil(err)
	suite.Nil(cinfo)
}

func (suite *TokenStoreTestSuite) TestAccessTokenStore() {
	ctx := context.Background()
	token := models.NewToken()
	token.SetClientID("1")
	token.SetUserID("1_1")
	token.SetRedirectURI("http://localhost/")
	token.SetScope("all")
	token.SetAccess("11_11_11")
	token.SetAccessCreateAt(time.Now())
	token.SetAccessExpiresIn(time.Second * 5)
	err := suite.store.Store(ctx, token)
	suite.Nil(err)

	ainfo, err := suite.store.GetByAccess(ctx, token.GetAccess())
	suite.Nil(err)
	suite.Equal(ainfo.GetUserID(), token.GetUserID())

	err = suite.store.RemoveByAccess(ctx, token.GetAccess())
	suite.Nil(err)

	ainfo, err = suite.store.GetByAccess(ctx, token.GetAccess())
	suite.Nil(err)
	suite.Nil(ainfo)
}

func (suite *TokenStoreTestSuite) TestRefreshTokenStore() {
	ctx := context.Background()
	token := models.NewToken()
	token.SetClientID("1")
	token.SetUserID("1_2")
	token.SetRedirectURI("http://localhost/")
	token.SetScope("all")
	token.SetAccess("1_2_1")
	token.SetAccessCreateAt(time.Now())
	token.SetAccessExpiresIn(time.Second * 5)
	token.SetRefresh("1_2_2")
	token.SetRefreshCreateAt(time.Now())
	token.SetRefreshExpiresIn(time.Second * 15)

	err := suite.store.Store(ctx, token)
	suite.Nil(err)

	rinfo, err := suite.store.GetByRefresh(ctx, token.GetRefresh())
	suite.Nil(err)
	suite.Equal(rinfo.GetUserID(), token.GetUserID())

	err = suite.store.RemoveByRefresh(ctx, token.GetRefresh())
	suite.Nil(err)

	rinfo, err = suite.store.GetByRefresh(ctx, token.GetRefresh())
	suite.Nil(err)
	suite.Nil(rinfo)
}

func (suite *TokenStoreTestSuite) TestTimeToLive() {
	ctx := context.Background()
	token := models.NewToken()
	token.SetClientID("1")
	token.SetUserID("1_2")
	token.SetRedirectURI("http://localhost/")
	token.SetScope("all")
	token.SetAccess("1_2_1")
	token.SetAccessCreateAt(time.Now())
	token.SetAccessExpiresIn(time.Second * 5)
	token.SetRefresh("1_2_2")
	token.SetRefreshCreateAt(time.Now())
	token.SetRefreshExpiresIn(time.Second * 1)
	err := suite.store.Store(ctx, token)
	suite.Nil(err)

	time.Sleep(time.Second * 1)
	ainfo, err := suite.store.GetByAccess(ctx, token.GetAccess())
	suite.Nil(err)
	suite.Nil(ainfo)
	rinfo, err := suite.store.GetByRefresh(ctx, token.GetRefresh())
	suite.Nil(err)
	suite.Nil(rinfo)
}

func TestTokenStoreTestSuite(t *testing.T) {
	suite.Run(t, &TokenStoreTestSuite{})
}
