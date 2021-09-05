package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/superseriousbusiness/oauth2/pkg/models"
	"github.com/superseriousbusiness/oauth2/pkg/store"
)

type ClientStoreTestSuite struct {
	StoreTestSuite
}

func (suite *ClientStoreTestSuite) TestInMemClientStore() {
	clientStore := store.InMemClientStore()

	err := clientStore.Set(context.Background(), "1", models.NewClient("1", "2", "", ""))
	suite.Nil(err)

	cli, err := clientStore.GetByID(context.Background(), "1")
	suite.Nil(err)
	suite.NotNil(cli)
	suite.Equal("1", cli.GetID())
}

func TestClientStoreTestSuite(t *testing.T) {
	suite.Run(t, &ClientStoreTestSuite{})
}
