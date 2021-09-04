package generates

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"

	"github.com/google/uuid"
)

// Authorize generate the authorization code interface
type Authorize interface {
	Token(ctx context.Context, data *Basic) (code string, err error)
}

// NewAuthorize create to generate the authorize code instance
func NewAuthorize() Authorize {
	return &authorize{}
}

// AuthorizeGenerate generate the authorize code
type authorize struct{}

// Token based on the UUID generated token
func (a *authorize) Token(ctx context.Context, data *Basic) (string, error) {
	buf := bytes.NewBufferString(data.Client.GetID())
	buf.WriteString(data.UserID)
	token := uuid.NewMD5(uuid.Must(uuid.NewRandom()), buf.Bytes())
	code := base64.URLEncoding.EncodeToString([]byte(token.String()))
	code = strings.ToUpper(strings.TrimRight(code, "="))

	return code, nil
}
