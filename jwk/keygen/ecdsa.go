package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/raiqub/jose/jwk"
)

func newECDSAKey(alg string) (*ecdsa.PrivateKey, error) {
	var curve elliptic.Curve
	switch alg {
	case "ES256":
		curve = elliptic.P256()
	case "ES384":
		curve = elliptic.P384()
	case "ES512":
		curve = elliptic.P521()
	default:
		return nil, jwk.UnhandledAlgorithm(alg)
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, ErrorGeneratingKey(err.Error())
	}

	return key, nil
}
