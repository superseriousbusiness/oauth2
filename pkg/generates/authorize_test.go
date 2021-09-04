package generates_test

import (
	"context"
	"testing"
	"time"

	"github.com/superseriousbusiness/oauth2/pkg/generates"
	"github.com/superseriousbusiness/oauth2/pkg/models"

	. "github.com/smartystreets/goconvey/convey"
)

func TestAuthorize(t *testing.T) {
	Convey("Test Authorize Generate", t, func() {
		data := &generates.Basic{
			Client:   models.New("123456", "123456", "", ""),
			UserID:   "000000",
			CreateAt: time.Now(),
		}
		gen := generates.NewAuthorize()
		code, err := gen.Token(context.Background(), data)
		So(err, ShouldBeNil)
		So(code, ShouldNotBeEmpty)
		Println("\nAuthorize Code:" + code)
	})
}
