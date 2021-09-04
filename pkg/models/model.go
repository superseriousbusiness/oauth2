package models

// ClientPasswordVerifier the password handler interface
type ClientPasswordVerifier interface {
	VerifyPassword(string) bool
}
