package models

// Client represents an oauth2 client.
type Client interface {
	GetID() string
	GetSecret() string
	GetDomain() string
	GetUserID() string
}

// NewClient returns a new simple client implementation with the given parameters.
func NewClient(id string, secret string, domain string, userID string) Client {
	return &simpleClient{
		id:     id,
		secret: secret,
		domain: domain,
		userID: userID,
	}
}

// simpleClient is a very simple client model that satisfies the Client interface
type simpleClient struct {
	id     string
	secret string
	domain string
	userID string
}

func (c *simpleClient) GetID() string {
	return c.id
}

func (c *simpleClient) GetSecret() string {
	return c.secret
}

func (c *simpleClient) GetDomain() string {
	return c.domain
}

func (c *simpleClient) GetUserID() string {
	return c.userID
}
