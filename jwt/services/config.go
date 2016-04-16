package services

import (
	"time"

	"github.com/raiqub/jose/jwk"
)

// A Config allows to define settings for Signer service.
type Config struct {
	Issuer    string
	SetURL    string
	SignKeyID string
	Duration  time.Duration
}

// A Cache represents the loaded keys by Signer or Verifier service.
type Cache struct {
	JWK    jwk.Key
	RawKey interface{}
}
