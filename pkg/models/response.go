package models

// ResponseType the type of authorization request
type ResponseType string

// define the type of authorization request
const (
	ResponseTypeCode  ResponseType = "code"
	ResponseTypeToken ResponseType = "token"
)

func (rt ResponseType) String() string {
	return string(rt)
}
