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
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"io"
	"io/ioutil"
	"runtime"
)

// Implements the HMAC-SHA family of signing methods signing methods
type SigningMethodHMAC struct {
	Name string
	Hash crypto.Hash
}

// Specific instances for HS256 and company
var (
	SigningMethodHS256 *SigningMethodHMAC
	SigningMethodHS384 *SigningMethodHMAC
	SigningMethodHS512 *SigningMethodHMAC
)

func init() {
	// HS256
	SigningMethodHS256 = &SigningMethodHMAC{"HS256", crypto.SHA256}
	RegisterSigningMethod(SigningMethodHS256.Alg(), func() SigningMethod {
		return SigningMethodHS256
	})

	// HS384
	SigningMethodHS384 = &SigningMethodHMAC{"HS384", crypto.SHA384}
	RegisterSigningMethod(SigningMethodHS384.Alg(), func() SigningMethod {
		return SigningMethodHS384
	})

	// HS512
	SigningMethodHS512 = &SigningMethodHMAC{"HS512", crypto.SHA512}
	RegisterSigningMethod(SigningMethodHS512.Alg(), func() SigningMethod {
		return SigningMethodHS512
	})
}

func (m *SigningMethodHMAC) Alg() string {
	return m.Name
}

// Verify the signature of HSXXX tokens.  Returns nil if the signature is valid.
func (m *SigningMethodHMAC) Verify(
	input, signature io.Reader,
	key interface{},
) error {
	// Verify the key is the right type
	keyBytes, ok := key.([]byte)
	if !ok {
		return ErrInvalidKey(0)
	}

	// Can we use the specified hashing method?
	if !m.Hash.Available() {
		return ErrHashUnavailable(m.Name)
	}

	// Decode signature, for comparison
	var sig []byte
	var err error
	if runtime.Version()[:5] == "go1.5" {
		// Buggy base64 Decoder (Go 1.5)
		// Test code: http://play.golang.org/p/O4NzYl9C6e
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

// Implements the Sign method from SigningMethod for this signing method.
// Key must be []byte
func (m *SigningMethodHMAC) Sign(
	input io.Reader,
	key interface{},
) (string, error) {
	// Verify the key is the right type
	keyBytes, ok := key.([]byte)
	if !ok {
		return "", ErrInvalidKey(0)
	}

	// Can we use the specified hashing method?
	if !m.Hash.Available() {
		return "", ErrHashUnavailable(m.Name)
	}

	// Generate a signature for input data
	hasher := hmac.New(m.Hash.New, keyBytes)
	if _, err := io.Copy(hasher, input); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)), nil
}
