package services

import (
	"github.com/raiqub/jose/jwk"
	"gopkg.in/raiqub/web.v0"
)

// A SetService defines an interface for a service that provides the key set
// used for signing or encrypting session tokens.
type SetService interface {
	GetCerts() (*jwk.Set, *web.JSONError)
}
