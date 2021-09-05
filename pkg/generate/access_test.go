package generate_test

import (
	"context"
	"testing"
	"time"

	"github.com/superseriousbusiness/oauth2/pkg/generate"
	"github.com/superseriousbusiness/oauth2/pkg/models"

	"github.com/stretchr/testify/suite"
)

type AccessTestSuite struct {
	GenerateTestSuite
}

func (suite *AccessTestSuite) TestDefaultAccessTokenGenerator() {
	data := &generate.Parameters{
		Client:   models.NewClient("a189fcd4-f1b5-477c-b9a1-df4f9c0a992d", "", "", ""),
		UserID:   "81439d0e-7e20-4564-ac9a-76cba6b7446f",
		CreateAt: time.Now(),
	}
	gen := generate.DefaultAccessTokenGenerator()
	access, refresh, err := gen.Token(context.Background(), data, true)
	suite.Nil(err)
	suite.Len(access, 48)
	suite.Len(refresh, 48)
	suite.T().Logf("got access  token %s", access)
	suite.T().Logf("got refresh token %s", refresh)
}

func (suite *AccessTestSuite) TestDefaultAccessTokenGeneratorNoParams() {
	data := &generate.Parameters{}
	gen := generate.DefaultAccessTokenGenerator()

	suite.Panics(func() {
		gen.Token(context.Background(), data, true)
	})
}

func TestAccessTestSuite(t *testing.T) {
	suite.Run(t, &AccessTestSuite{})
}
