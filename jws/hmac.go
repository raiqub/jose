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
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"io"
	"io/ioutil"
	"runtime"

	// Imports to ensure hash functions registration.
	_ "crypto/sha256"
	_ "crypto/sha512"
)

type hmacAlg struct {
	crypto.Hash
}

func init() {
	RegisterAlgorithm(HS256, func() SigningMethod {
		return hmacAlg{crypto.SHA256}
	})

	RegisterAlgorithm(HS384, func() SigningMethod {
		return hmacAlg{crypto.SHA384}
	})

	RegisterAlgorithm(HS512, func() SigningMethod {
		return hmacAlg{crypto.SHA512}
	})
}

func (m hmacAlg) Verify(input, signature io.Reader, key interface{}) error {
	// Verify the key is the right type
	keyBytes, ok := key.([]byte)
	if !ok {
		return ErrInvalidKey(0)
	}

	// Can we use the specified hashing method?
	if !m.Hash.Available() {
		return ErrHashUnavailable(m.Hash)
	}

	// Decode signature, for comparison
	var sig []byte
	var err error
	if runtime.Version()[:5] == "go1.5" {
		// Buggy base64 Decoder (Go 1.5)
		buf, err := ioutil.ReadAll(signature)
		if err != nil {
			return err
		}
		sig, err = base64.RawURLEncoding.DecodeString(string(buf))
		if err != nil {
			return err
		}
	} else {
		sig, err = ioutil.ReadAll(
			base64.NewDecoder(base64.RawURLEncoding, signature))
		if err != nil {
			return err
		}
	}

	// This signing method is symmetric, so we validate the signature
	// by reproducing the signature from the signing string and key, then
	// comparing that against the provided signature.
	hasher := hmac.New(m.Hash.New, keyBytes)
	if _, err := io.Copy(hasher, input); err != nil {
		return err
	}
	if !hmac.Equal(sig, hasher.Sum(nil)) {
		return ErrSignatureInvalid(0)
	}

	// No validation errors.  Signature is good.
	return nil
}

func (m hmacAlg) Sign(input io.Reader, key interface{}) (string, error) {
	// Verify the key is the right type
	keyBytes, ok := key.([]byte)
	if !ok {
		return "", ErrInvalidKey(0)
	}

	// Can we use the specified hashing method?
	if !m.Hash.Available() {
		return "", ErrHashUnavailable(m.Hash)
	}

	// Generate a signature for input data
	hasher := hmac.New(m.Hash.New, keyBytes)
	if _, err := io.Copy(hasher, input); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)), nil
}
