package generate_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/superseriousbusiness/oauth2/pkg/generate"
	"github.com/superseriousbusiness/oauth2/pkg/models"
)

type AuthorizeTestSuite struct {
	GenerateTestSuite
}

func (suite *AuthorizeTestSuite) TestGenerateAuthorize() {
	params := &generate.Parameters{
		Client:   models.NewClient("a189fcd4-f1b5-477c-b9a1-df4f9c0a992d", "", "", ""),
		UserID:   "81439d0e-7e20-4564-ac9a-76cba6b7446f",
		CreateAt: time.Now(),
	}
	gen := generate.DefaultAuthorizationTokenGenerator()
	authorizationCode, err := gen.Token(context.Background(), params)
	suite.Nil(err)
	suite.NotEmpty(authorizationCode)
	suite.T().Logf("got authorization token %s", authorizationCode)
}

func TestAuthorizeTestSuite(t *testing.T) {
	suite.Run(t, &AuthorizeTestSuite{})
}
