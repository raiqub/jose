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

package jwa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
	"math/big"
)

// ErrVerification represents a failure to verify a signature.
// It is deliberately vague to avoid adaptive attacks.
var ErrVerification = errors.New("jose/jws: verification error")

type ecdsaAlg struct {
	hashFunc  func() hash.Hash
	keySize   int
	curveBits int
}

func init() {
	RegisterAlgorithm(ES256, func() SigningMethod {
		return &ecdsaAlg{
			func() hash.Hash { return sha256.New() },
			32, 256,
		}
	})
	RegisterAlgorithm(ES384, func() SigningMethod {
		return &ecdsaAlg{
			func() hash.Hash { return sha512.New384() },
			48, 384,
		}
	})
	RegisterAlgorithm(ES512, func() SigningMethod {
		return &ecdsaAlg{
			func() hash.Hash { return sha512.New() },
			66, 521,
		}
	})
}

// Implements the Verify method from SigningMethod
// For this verify method, key must be an ecdsa.PublicKey struct
func (m *ecdsaAlg) Verify(input, signature string, key interface{}) error {
	// Decode PEM-encoded key
	if pem, ok := key.([]byte); ok {
		out, err := ParseECDSAFromPEM(pem)
		if err != nil {
			return err
		}

		key = out
	}

	var err error

	// Get the key
	var ecdsaKey *ecdsa.PublicKey
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		ecdsaKey = k
	case *ecdsa.PrivateKey:
		*ecdsaKey = k.Public().(ecdsa.PublicKey)
	default:
		return ErrInvalidKey{key}
	}

	// Decode the signature
	decSig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	if len(decSig) != 2*m.keySize {
		return ErrVerification
	}

	r := big.NewInt(0).SetBytes(decSig[:m.keySize])
	s := big.NewInt(0).SetBytes(decSig[m.keySize:])

	// Create hasher
	hasher := m.hashFunc()
	hasher.Write([]byte(input))

	// Verify the signature
	ok := ecdsa.Verify(ecdsaKey, hasher.Sum(nil), r, s)
	if !ok {
		return ErrVerification
	}

	return nil
}

// Implements the Sign method from SigningMethod
// For this signing method, key must be an ecdsa.PrivateKey struct
func (m *ecdsaAlg) Sign(input string, key interface{}) (string, error) {
	// Decode PEM-encoded key
	if pem, ok := key.([]byte); ok {
		out, err := ParseECDSAFromPEM(pem)
		if err != nil {
			return "", err
		}

		key = out
	}

	// Get the key
	var ecdsaKey *ecdsa.PrivateKey
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		ecdsaKey = k
	default:
		return "", ErrInvalidKey{key}
	}

	// Create the hasher
	hasher := m.hashFunc()
	hasher.Write([]byte(input))

	// Sign the string and return r, s
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hasher.Sum(nil))
	if err != nil {
		return "", err
	}

	curveBits := ecdsaKey.Curve.Params().BitSize

	if m.curveBits != curveBits {
		return "", ErrInvalidKey{key}
	}

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	// We serialize the outpus (r and s) into big-endian byte arrays and pad
	// them with zeros on the left to make sure the sizes work out. Both arrays
	// must be keyBytes long, and the output must be 2*keyBytes long.
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	buf := make([]byte, keyBytes*2)
	copy(buf[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(buf[keyBytes*2-len(sBytes):], sBytes)

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (m *ecdsaAlg) GenerateKey(int) (interface{}, error) {
	var curve elliptic.Curve
	switch m.curveBits {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		return nil, ErrorGeneratingKey(
			"Unsupported elliptic curve size")
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, ErrorGeneratingKey(err.Error())
	}

	return key, nil
}
