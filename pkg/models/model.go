package models

// ClientPasswordVerifier wraps logic for verifying a client password.
type ClientPasswordVerifier interface {
	// VerifyPassword returns true if the given password is valid, or false if not.
	VerifyPassword(password string) bool
}
