package generates

import (
	"net/http"
	"time"

	"github.com/superseriousbusiness/oauth2/pkg/models"
)

// Basic provide the basis of the generated token data
type Basic struct {
	Client    models.ClientInfo
	UserID    string
	CreateAt  time.Time
	TokenInfo models.TokenInfo
	Request   *http.Request
}
