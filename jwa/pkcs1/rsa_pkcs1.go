/*
 * Copyright 2012 Dave Grijalva
 * Copyright 2016 Fabrício Godoy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package pkcs1

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"

	"github.com/raiqub/jose/jwa"
	jwarsa "github.com/raiqub/jose/jwa/rsa"
)

const (
	// MinimumRSAKeySize defines the minimum key size for RSA keys as
	// recommended by security experts.
	MinimumRSAKeySize = 2048
)

type rsaPKCS1Alg struct {
	hashAlg  crypto.Hash
	hashFunc func() hash.Hash
}

func init() {
	jwa.RegisterAlgorithm(jwa.RS256, New256)
	jwa.RegisterAlgorithm(jwa.RS384, New384)
	jwa.RegisterAlgorithm(jwa.RS512, New512)
}

// New256 returns a new RS256 cryptographic algorithm.
func New256() jwa.Algorithm {
	return &rsaPKCS1Alg{
		crypto.SHA256,
		func() hash.Hash { return sha256.New() },
	}
}

// New384 returns a new RS384 cryptographic algorithm.
func New384() jwa.Algorithm {
	return &rsaPKCS1Alg{
		crypto.SHA384,
		func() hash.Hash { return sha512.New384() },
	}
}

// New512 returns a new RS512 cryptographic algorithm.
func New512() jwa.Algorithm {
	return &rsaPKCS1Alg{
		crypto.SHA512,
		func() hash.Hash { return sha512.New() },
	}
}

// Implements the Verify method from SigningMethod
// For this signing method, must be either a PEM encoded PKCS1 or PKCS8 RSA public key as
// []byte, or an rsa.PublicKey structure.
func (m *rsaPKCS1Alg) Verify(input, signature string, key interface{}) error {
	var err error

	// Decode PEM-encoded key
	if pem, ok := key.([]byte); ok {
		out, err := jwarsa.ParseFromPEM(pem)
		if err != nil {
			return err
		}

		key = out
	}

	// Verify the key is the right type
	var rsaKey *rsa.PublicKey
	switch k := key.(type) {
	case *rsa.PublicKey:
		rsaKey = k
	case *rsa.PrivateKey:
		rsaKey = k.Public().(*rsa.PublicKey)
	default:
		return jwa.ErrInvalidKey{Value: key}
	}

	// Decode the signature
	decSig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	// Create hasher
	hasher := m.hashFunc()
	hasher.Write([]byte(input))

	// Verify the signature
	return rsa.VerifyPKCS1v15(rsaKey, m.hashAlg, hasher.Sum(nil), decSig)
}

// Implements the Sign method from SigningMethod
// For this signing method, must be either a PEM encoded PKCS1 or PKCS8 RSA private key as
// []byte, or an rsa.PrivateKey structure.
func (m *rsaPKCS1Alg) Sign(input string, key interface{}) (string, error) {
	var err error

	// Decode PEM-encoded key
	if pem, ok := key.([]byte); ok {
		out, err := jwarsa.ParseFromPEM(pem)
		if err != nil {
			return "", err
		}

		key = out
	}

	var rsaKey *rsa.PrivateKey
	switch k := key.(type) {
	case *rsa.PrivateKey:
		rsaKey = k
	default:
		return "", jwa.ErrInvalidKey{Value: key}
	}

	// Create hasher
	hasher := m.hashFunc()
	hasher.Write([]byte(input))

	// Sign the string and return the encoded bytes
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaKey,
		m.hashAlg, hasher.Sum(nil))
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(sigBytes), nil
}

func (m *rsaPKCS1Alg) GenerateKey(bits int) (interface{}, error) {
	if bits < MinimumRSAKeySize {
		return nil, jwa.ErrTooSmallKeySize{
			Minimum: MinimumRSAKeySize,
			Actual:  bits,
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, jwa.ErrorGeneratingKey(err.Error())
	}

	return key, nil
}
