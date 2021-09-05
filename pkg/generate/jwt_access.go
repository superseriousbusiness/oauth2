package generate

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/superseriousbusiness/oauth2/pkg/errors"
)

// JWTGenerator wraps JWT token generation functionality.
type JWTGenerator interface {
	Token(ctx context.Context, data *Parameters, isGenRefresh bool) (string, string, error)
}

// JWTAccessClaims models standard JWT claims using golang-jwt/jwt
type JWTAccessClaims struct {
	jwt.StandardClaims
}

// Valid claims verification
func (a *JWTAccessClaims) Valid() error {
	if time.Unix(a.ExpiresAt, 0).Before(time.Now()) {
		return errors.ErrInvalidAccessToken
	}
	return nil
}

// DefaultJWTGenerator create to generate the jwt access token instance
func DefaultJWTGenerator(kid string, key []byte, method jwt.SigningMethod) JWTGenerator {
	return &jwtAccess{
		SignedKeyID:  kid,
		SignedKey:    key,
		SignedMethod: method,
	}
}

// jwtAccess generate the jwt access token
type jwtAccess struct {
	SignedKeyID  string
	SignedKey    []byte
	SignedMethod jwt.SigningMethod
}

func (a *jwtAccess) Token(ctx context.Context, data *Parameters, isGenRefresh bool) (string, string, error) {
	claims := &JWTAccessClaims{}
	claims.Audience = data.Client.GetID()
	claims.Subject = data.UserID
	claims.ExpiresAt = data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn()).Unix()

	token := jwt.NewWithClaims(a.SignedMethod, claims)
	if a.SignedKeyID != "" {
		token.Header["kid"] = a.SignedKeyID
	}
	var key interface{}
	if a.isEs() {
		v, err := jwt.ParseECPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else if a.isRsOrPS() {
		v, err := jwt.ParseRSAPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else if a.isHs() {
		key = a.SignedKey
	} else {
		return "", "", errors.New("unsupported sign method")
	}

	access, err := token.SignedString(key)
	if err != nil {
		return "", "", err
	}
	refresh := ""

	if isGenRefresh {
		t := uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()
		refresh = base64.URLEncoding.EncodeToString([]byte(t))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}

	return access, refresh, nil
}

func (a *jwtAccess) isEs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "ES")
}

func (a *jwtAccess) isRsOrPS() bool {
	isRs := strings.HasPrefix(a.SignedMethod.Alg(), "RS")
	isPs := strings.HasPrefix(a.SignedMethod.Alg(), "PS")
	return isRs || isPs
}

func (a *jwtAccess) isHs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "HS")
}
