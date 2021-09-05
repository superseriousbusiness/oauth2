package generate

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/superseriousbusiness/oauth2/pkg/util"
)

// AccessTokenGenerator wraps logic for generating access and refresh tokens.
type AccessTokenGenerator interface {
	// Token returns an access token based on the given parameters.
	// If generateRefresh is true, then a refresh token will also be returned.
	// If generateRefresh is empty, refresh will be an empty string.
	Token(ctx context.Context, generateParams *Parameters, generateRefresh bool) (access string, refresh string, err error)
}

// DefaultAccessTokenGenerator returns an AccessTokenGenerator with the default token generation logic:
//   1. concatenate client ID, userID, and creation time
//   2. md5 hash the result in a random namespace
//   3. base64 encode resulting bytes
//   4. uppercase base64
//
// RefreshToken is a random SHA1 hash of the concatenation produced by step 1.
func DefaultAccessTokenGenerator() AccessTokenGenerator {
	return &accessTokenGenerator{}
}

// accessTokenGenerator implements the AccessTokenGenerator interface.
type accessTokenGenerator struct{}

func (a *accessTokenGenerator) Token(ctx context.Context, generateParams *Parameters, generateRefresh bool) (string, string, error) {
	base := fmt.Sprintf("%s%s%d", generateParams.Client.GetID(), generateParams.UserID, generateParams.CreateAt.UnixNano())
	baseBytes := []byte(base)

	md5 := uuid.NewMD5(uuid.New(), baseBytes)
	access := util.B64Encode(md5.String())

	var refresh string
	if generateRefresh {
		sha1 := uuid.NewSHA1(uuid.New(), baseBytes)
		refresh = util.B64Encode(sha1.String())
	}

	return access, refresh, nil
}
