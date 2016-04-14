package keygen

import (
	"crypto/rand"
	"crypto/rsa"
)

const (
	// MinimumRSAKeySize defines the minimum key size for RSA keys as
	// recommended by security experts.
	MinimumRSAKeySize = 2048
)

func newRSAKey(alg string, size int) (*rsa.PrivateKey, error) {
	if size < MinimumRSAKeySize {
		return nil, TooSmallKeySize{MinimumRSAKeySize, size}
	}

	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, ErrorGeneratingKey(err.Error())
	}

	return key, nil
}
