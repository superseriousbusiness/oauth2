package generate_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/suite"
	"github.com/superseriousbusiness/oauth2/pkg/generate"
	"github.com/superseriousbusiness/oauth2/pkg/models"
)

type JWTTestSuite struct {
	GenerateTestSuite
}

func (suite *JWTTestSuite) TestGenerateJWT() {
	tokenInfo := models.NewToken()
	tokenInfo.SetAccessCreateAt(time.Now())
	tokenInfo.SetAccessExpiresIn(time.Second * 120)

	data := &generate.Parameters{
		Client:    models.NewClient("123456", "123456", "", ""),
		UserID:    "000000",
		TokenInfo: tokenInfo,
	}

	gen := generate.DefaultJWTGenerator("", []byte("00000000"), jwt.SigningMethodHS512)
	access, refresh, err := gen.Token(context.Background(), data, true)
	suite.Nil(err)
	suite.NotEmpty(access)
	suite.NotEmpty(refresh)

	token, err := jwt.ParseWithClaims(access, &generate.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("parse error")
		}
		return []byte("00000000"), nil
	})
	suite.Nil(err)

	claims, ok := token.Claims.(*generate.JWTAccessClaims)
	suite.True(ok)
	suite.True(token.Valid)
	suite.Equal("123456", claims.Audience)
	suite.Equal("000000", claims.Subject)
}

func TestJWTTestSuite(t *testing.T) {
	suite.Run(t, &JWTTestSuite{})
}
