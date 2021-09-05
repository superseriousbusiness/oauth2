package generate

import (
	"net/url"
	"strings"

	"github.com/superseriousbusiness/oauth2/pkg/errors"
)

const oob = "urn:ietf:wg:oauth:2.0:oob"

// RedirectValidationHandler validates that the given redirectURI is valid for the given baseURI.
type RedirectValidationHandler func(baseURI string, redirectURI string) error

// DefaultRedirectValidation is the default RedirectValidationHandler.
// It performs validation by simply parsing the baseURI, parsing the redirectURI,
// and then checking if the redirect host has the base host as a suffix.
var DefaultRedirectValidation RedirectValidationHandler = func(baseURI string, redirectURI string) error {
	baseURL, err := url.Parse(baseURI)
	if err != nil {
		return err
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		return err
	}

	if !strings.HasSuffix(redirectURL.Host, baseURL.Host) {
		return errors.ErrInvalidRedirectURI
	}

	return nil
}

// OOBRedirectValidation performs the same functionality as DefaultRedirectValidation, but it
// will also allow out-of-bounds redirection, with the value 'urn:ietf:wg:oauth:2.0:oob'.
var OOBRedirectValidation RedirectValidationHandler = func(baseURI string, redirectURI string) error {
	if redirectURI == oob {
		return nil
	}

	return DefaultRedirectValidation(baseURI, redirectURI)
}
