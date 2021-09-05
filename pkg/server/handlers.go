package server

import (
	"net/http"
	"time"

	"github.com/superseriousbusiness/oauth2/pkg/errors"
	"github.com/superseriousbusiness/oauth2/pkg/models"
)

type (
	// ClientInfoHandler parses the clientID and clientSecret from a request.
	ClientInfoHandler func(r *http.Request) (clientID string, clientSecret string, err error)

	// ClientAuthorizedHandler check the client allows to use this authorization grant type
	ClientAuthorizedHandler func(clientID string, grant models.GrantType) (allowed bool, err error)

	// ClientScopeHandler check the client allows to use scope
	ClientScopeHandler func(tgr *models.TokenGenerateRequest) (allowed bool, err error)

	// UserAuthorizationHandler get user id from request authorization
	UserAuthorizationHandler func(w http.ResponseWriter, r *http.Request) (userID string, err error)

	// PasswordAuthorizationHandler get user id from username and password
	PasswordAuthorizationHandler func(username, password string) (userID string, err error)

	// RefreshingScopeHandler check the scope of the refreshing token
	RefreshingScopeHandler func(tgr *models.TokenGenerateRequest, oldScope string) (allowed bool, err error)

	// RefreshingValidationHandler check if refresh_token is still valid. eg no revocation or other
	RefreshingValidationHandler func(ti models.Token) (allowed bool, err error)

	// ResponseErrorHandler response error handing
	ResponseErrorHandler func(re *errors.Response)

	// InternalErrorHandler internal error handing
	InternalErrorHandler func(err error) (re *errors.Response)

	// AuthorizeScopeHandler set the authorized scope
	AuthorizeScopeHandler func(w http.ResponseWriter, r *http.Request) (scope string, err error)

	// AccessTokenExpHandler set expiration date for the access token
	AccessTokenExpHandler func(w http.ResponseWriter, r *http.Request) (exp time.Duration, err error)

	// ExtensionFieldsHandler in response to the access token with the extension of the field
	ExtensionFieldsHandler func(ti models.Token) (fieldsValue map[string]interface{})
)

// SetClientInfoHandler get client info from request
func (s *Server) SetClientInfoHandler(handler ClientInfoHandler) {
	s.clientInfoHandler = handler
}

// SetClientAuthorizedHandler check the client allows to use this authorization grant type
func (s *Server) SetClientAuthorizedHandler(handler ClientAuthorizedHandler) {
	s.clientAuthorizedHandler = handler
}

// SetClientScopeHandler check the client allows to use scope
func (s *Server) SetClientScopeHandler(handler ClientScopeHandler) {
	s.clientScopeHandler = handler
}

// SetUserAuthorizationHandler get user id from request authorization
func (s *Server) SetUserAuthorizationHandler(handler UserAuthorizationHandler) {
	s.userAuthHandler = handler
}

// SetPasswordAuthorizationHandler get user id from username and password
func (s *Server) SetPasswordAuthorizationHandler(handler PasswordAuthorizationHandler) {
	s.passwordAuthHandler = handler
}

// SetRefreshingScopeHandler check the scope of the refreshing token
func (s *Server) SetRefreshingScopeHandler(handler RefreshingScopeHandler) {
	s.refreshScopeHandler = handler
}

// SetRefreshingValidationHandler check if refresh_token is still valid. eg no revocation or other
func (s *Server) SetRefreshingValidationHandler(handler RefreshingValidationHandler) {
	s.refreshValidationHandler = handler
}

// SetResponseErrorHandler response error handling
func (s *Server) SetResponseErrorHandler(handler ResponseErrorHandler) {
	s.responseErrorHandler = handler
}

// SetInternalErrorHandler internal error handling
func (s *Server) SetInternalErrorHandler(handler InternalErrorHandler) {
	s.internalErrorHandler = handler
}

// SetExtensionFieldsHandler in response to the access token with the extension of the field
func (s *Server) SetExtensionFieldsHandler(handler ExtensionFieldsHandler) {
	s.extensionFieldsHandler = handler
}

// SetAccessTokenExpHandler set expiration date for the access token
func (s *Server) SetAccessTokenExpHandler(handler AccessTokenExpHandler) {
	s.accessTokenExpHandler = handler
}

// SetAuthorizeScopeHandler set scope for the access token
func (s *Server) SetAuthorizeScopeHandler(handler AuthorizeScopeHandler) {
	s.authorizeScopeHandler = handler
}

// ClientInfoHandlerForm satisfies ClientInfoHandler by extracting values from the request form.
// It will search for the following keys in the form:
//   client_id
//   client_secret
var ClientInfoHandlerForm ClientInfoHandler = func(r *http.Request) (string, string, error) {
	clientID := r.Form.Get("client_id")
	if clientID == "" {
		return "", "", errors.ErrInvalidClient
	}
	clientSecret := r.Form.Get("client_secret")
	return clientID, clientSecret, nil
}

// ClientInfoHandlerBasicAuth satisfies ClientInfoHandler by extracting values from the basic auth.
//   clientID = username
//   clientSecret = password
var ClientInfoHandlerBasicAuth ClientInfoHandler = func(r *http.Request) (string, string, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return "", "", errors.ErrInvalidClient
	}
	return username, password, nil
}
