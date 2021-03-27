package generates_test

import (
	"context"
	"testing"
	"time"

	"github.com/superseriousbusiness/oauth2/v4"
	"github.com/superseriousbusiness/oauth2/v4/generates"
	"github.com/superseriousbusiness/oauth2/v4/models"

	. "github.com/smartystreets/goconvey/convey"
)

func TestAccess(t *testing.T) {
	Convey("Test Access Generate", t, func() {
		data := &oauth2.GenerateBasic{
			Client: models.New("123456", "123456", "", ""),
			UserID:   "000000",
			CreateAt: time.Now(),
		}
		gen := generates.NewAccessGenerate()
		access, refresh, err := gen.Token(context.Background(), data, true)
		So(err, ShouldBeNil)
		So(access, ShouldNotBeEmpty)
		So(refresh, ShouldNotBeEmpty)
		Println("\nAccess Token:" + access)
		Println("Refresh Token:" + refresh)
	})
}
