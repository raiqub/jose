package services

import (
	"fmt"
)

// An ErrUnexpectedAlg represents an error when a token uses an unexpected
// algorithm for its signature.
type ErrUnexpectedAlg string

// Error returns string representation of current instance error.
func (e ErrUnexpectedAlg) Error() string {
	return fmt.Sprintf("Unexpected algorithm: %s", string(e))
}

// An ErrInvalidKeyID represents an error when the key identifier used to sign a
// token could not be found.
type ErrInvalidKeyID string

// Error returns string representation of current instance error.
func (e ErrInvalidKeyID) Error() string {
	return fmt.Sprintf("Invalid key ID: %s", string(e))
}

// An ErrInvalidToken represents an error when a token is not valid.
type ErrInvalidToken int

// Error returns string representation of current instance error.
func (e ErrInvalidToken) Error() string {
	return "Invalid token"
}
