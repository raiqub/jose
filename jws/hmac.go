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

package jws

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
)

type hmacAlg struct {
	hashFunc func() hash.Hash
}

func init() {
	RegisterAlgorithm(HS256, func() SigningMethod {
		return hmacAlg{func() hash.Hash { return sha256.New() }}
	})

	RegisterAlgorithm(HS384, func() SigningMethod {
		return hmacAlg{func() hash.Hash { return sha512.New384() }}
	})

	RegisterAlgorithm(HS512, func() SigningMethod {
		return hmacAlg{func() hash.Hash { return sha512.New() }}
	})
}

func (m hmacAlg) Verify(input, signature string, key interface{}) error {
	// Verify the key is the right type
	keyBytes, ok := key.([]byte)
	if !ok {
		return ErrInvalidKey{key}
	}

	// Decode signature, for comparison
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	// This signing method is symmetric, so we validate the signature
	// by reproducing the signature from the signing string and key, then
	// comparing that against the provided signature.
	hasher := hmac.New(m.hashFunc, keyBytes)
	if _, err := hasher.Write([]byte(input)); err != nil {
		return err
	}
	if !hmac.Equal(sig, hasher.Sum(nil)) {
		return ErrSignatureInvalid(0)
	}

	// No validation errors.  Signature is good.
	return nil
}

func (m hmacAlg) Sign(input string, key interface{}) (string, error) {
	// Verify the key is the right type
	keyBytes, ok := key.([]byte)
	if !ok {
		return "", ErrInvalidKey{key}
	}

	// Generate a signature for input data
	hasher := hmac.New(m.hashFunc, keyBytes)
	if _, err := hasher.Write([]byte(input)); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)), nil
}
