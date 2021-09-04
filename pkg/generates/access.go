package generates

import (
	"bytes"
	"context"
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// Access generate the access and refresh tokens interface
type Access interface {
	Token(ctx context.Context, data *Basic, isGenRefresh bool) (access, refresh string, err error)
}


// NewAccess create to generate the access token instance
func NewAccess() Access {
	return &access{}
}

// AccessGenerate generate the access token
type access struct{}

// Token based on the UUID generated token
func (a *access) Token(ctx context.Context, data *Basic, isGenRefresh bool) (string, string, error) {
	buf := bytes.NewBufferString(data.Client.GetID())
	buf.WriteString(data.UserID)
	buf.WriteString(strconv.FormatInt(data.CreateAt.UnixNano(), 10))

	access := base64.URLEncoding.EncodeToString([]byte(uuid.NewMD5(uuid.Must(uuid.NewRandom()), buf.Bytes()).String()))
	access = strings.ToUpper(strings.TrimRight(access, "="))
	refresh := ""
	if isGenRefresh {
		refresh = base64.URLEncoding.EncodeToString([]byte(uuid.NewSHA1(uuid.Must(uuid.NewRandom()), buf.Bytes()).String()))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}

	return access, refresh, nil
}
