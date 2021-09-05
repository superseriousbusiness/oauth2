package generate

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/superseriousbusiness/oauth2/pkg/util"
)

// AuthorizationTokenGenerator generate the authorization code interface
type AuthorizationTokenGenerator interface {
	Token(ctx context.Context, generateParams *Parameters) (code string, err error)
}

// DefaultAuthorizationTokenGenerator returns a default AuthorizationTokenGenerator.
func DefaultAuthorizationTokenGenerator() AuthorizationTokenGenerator {
	return &authorizationTokenGenerator{}
}

// AuthorizeGenerate generate the authorizationTokenGenerator code
type authorizationTokenGenerator struct{}

// Token based on the UUID generated token
func (a *authorizationTokenGenerator) Token(ctx context.Context, generateParams *Parameters) (string, error) {
	base := fmt.Sprintf("%s%s", generateParams.Client.GetID(), generateParams.UserID)
	baseBytes := []byte(base)

	md5 := uuid.NewMD5(uuid.New(), baseBytes)
	code := util.B64Encode(md5.String())

	return code, nil
}
