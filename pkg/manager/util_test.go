package manager_test

import (
	"testing"

	"github.com/superseriousbusiness/oauth2/pkg/manager"

	. "github.com/smartystreets/goconvey/convey"
)

func TestUtil(t *testing.T) {
	Convey("Util Test", t, func() {
		Convey("ValidateURI Test", func() {
			err := manager.DefaultValidateURI("http://www.example.com", "http://www.example.com/cb?code=xxx")
			So(err, ShouldBeNil)
		})
	})
}
