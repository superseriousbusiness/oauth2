package generate_test

import (
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/superseriousbusiness/oauth2/pkg/errors"
	"github.com/superseriousbusiness/oauth2/pkg/generate"
)

type RedirectTestSuite struct {
	GenerateTestSuite
}

func (suite *RedirectTestSuite) TestDefaultRedirectValidation() {
	err := generate.DefaultRedirectValidation("http://www.example.org", "http://www.example.org/cb?code=xxx")
	suite.Nil(err)

	err = generate.DefaultRedirectValidation("http://example.org", "http://application.example.org/cb?code=xxx")
	suite.Nil(err)

	err = generate.DefaultRedirectValidation("http://example.com", "http://example.org/cb?code=xxx")
	suite.ErrorIs(err, errors.ErrInvalidRedirectURI)

	err = generate.DefaultRedirectValidation("http://www.example.org", "urn:ietf:wg:oauth:2.0:oob")
	suite.ErrorIs(err, errors.ErrInvalidRedirectURI)
}

func (suite *RedirectTestSuite) TestOOBRedirectValidation() {
	err := generate.OOBRedirectValidation("http://www.example.org", "urn:ietf:wg:oauth:2.0:oob")
	suite.Nil(err)

	err = generate.OOBRedirectValidation("http://www.example.org", "urn:ietf:wg:oa     uth:2.0:oob")
	suite.Error(err)

	err = generate.OOBRedirectValidation("http://www.example.org", "http://www.example.org/cb?code=xxx")
	suite.Nil(err)

	err = generate.OOBRedirectValidation("http://example.org", "http://application.example.org/cb?code=xxx")
	suite.Nil(err)

	err = generate.OOBRedirectValidation("http://example.com", "http://example.org/cb?code=xxx")
	suite.ErrorIs(err, errors.ErrInvalidRedirectURI)
}

func TestRedirectTestSuite(t *testing.T) {
	suite.Run(t, &RedirectTestSuite{})
}
