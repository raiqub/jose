package services

import (
	"time"

	"github.com/raiqub/jose/jwk"
)

type Config struct {
	Issuer    string
	SetURL    string
	SignKeyId string
	Duration  time.Duration
}

type Cache struct {
	JWK    jwk.Key
	RawKey interface{}
}
