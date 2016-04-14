package keygen

import (
	"time"

	"github.com/raiqub/jose/jwk"
)

// New generates a new key based on parameters settings.
func New(alg string, size, days int) (*jwk.Key, error) {
	if len(alg) != 5 {
		return nil, jwk.UnhandledAlgorithm(alg)
	}
	switch alg[2:] {
	case "256", "384", "512":
	default:
		return nil, jwk.UnhandledAlgorithm(alg)
	}

	var key interface{}
	var err error
	switch alg[0:2] {
	case "ES":
		key, err = newECDSAKey(alg)
	case "HS":
		key, err = newSymKey(alg, size)
	case "RS", "PS":
		key, err = newRSAKey(alg, size)
	default:
		return nil, jwk.UnhandledAlgorithm(alg)
	}

	if err != nil {
		return nil, err
	}

	now := time.Now()
	jwkKey := jwk.Key{
		Usage:     "sig",
		NotBefore: now,
		ExpireAt:  now.Add(time.Hour * 24 * time.Duration(days)),
	}
	if err := jwkKey.SetKey(key, alg); err != nil {
		return nil, err
	}

	return &jwkKey, nil
}
