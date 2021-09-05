package generate

import (
	"net/http"
	"time"

	"github.com/superseriousbusiness/oauth2/pkg/models"
)

// Parameters is used to pass token generation parameters into the token generation functions.
type Parameters struct {
	Client    models.Client
	UserID    string
	CreateAt  time.Time
	TokenInfo models.Token
	Request   *http.Request
}
