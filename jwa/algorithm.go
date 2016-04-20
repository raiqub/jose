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

// Algorithm represents a code for cryptographic algorithm to digitally
// sign or create a MAC of the input data.
type Algorithm interface {
	// Verify whether a signature matches the input data.
	Verify(input, signature string, key interface{}) error

	// Sign generates a signature for input data.
	Sign(input string, key interface{}) (string, error)

	// GenerateKey generates a key pair of the given bit size, or for symmetric
	// algorithms generates a single key of the given bit size.
	GenerateKey(bits int) (interface{}, error)
}

// An AlgorithmCode represents a code for cryptographic algorithm to digitally
// sign or create a MAC of the token header and payload.
//type AlgorithmCode string

// List of available algorithms as defined by JWA specification.
// Ref: https://tools.ietf.org/html/rfc7518#section-3.1.
const (
	// HS256 defines an HMAC algorithm using SHA-256.
	HS256 = "HS256" // import github.com/raiqub/jose/jwa/hmac

	// HS384 defines an HMAC algorithm using SHA-384.
	HS384 = "HS384" // import github.com/raiqub/jose/jwa/hmac

	// HS384 defines an HMAC algorithm using SHA-512.
	HS512 = "HS512" // import github.com/raiqub/jose/jwa/hmac

	// RS256 defines an RSASSA-PKCS1-v1_5 algorithm using SHA-256.
	RS256 = "RS256" // import github.com/raiqub/jose/jwa/pkcs1

	// RS384 defines an RSASSA-PKCS1-v1_5 algorithm using SHA-384.
	RS384 = "RS384" // import github.com/raiqub/jose/jwa/pkcs1

	// RS512 defines an RSASSA-PKCS1-v1_5 algorithm using SHA-512.
	RS512 = "RS512" // import github.com/raiqub/jose/jwa/pkcs1

	// ES256 defines an ECDSA algorithm using P-256 and SHA-256.
	ES256 = "ES256" // import github.com/raiqub/jose/jwa/ecdsa

	// ES384 defines an ECDSA algorithm using P-384 and SHA-384.
	ES384 = "ES384" // import github.com/raiqub/jose/jwa/ecdsa

	// ES384 defines an ECDSA algorithm using P-521 and SHA-512.
	ES512 = "ES512" // import github.com/raiqub/jose/jwa/ecdsa

	// ES256 defines an RSASSA-PSS algorithm using SHA-256 and MGF1 with
	// SHA-256.
	PS256 = "PS256"

	// ES384 defines an RSASSA-PSS algorithm using SHA-384 and MGF1 with
	// SHA-384.
	PS384 = "PS384"

	// ES384 defines an RSASSA-PSS algorithm using SHA-512 and MGF1 with
	// SHA-512.
	PS512 = "PS512"
)

var algorithms = map[string]func() Algorithm{}

// New returns a new Algorithm for signing or verifying tokens and generating
// keys. Returns ErrAlgUnavailable when the algorithm is not implemented.
func New(alg string) (Algorithm, error) {
	if m, ok := algorithms[alg]; ok {
		return m(), nil
	}

	return nil, ErrAlgUnavailable(alg)
}

// Available reports whether an implementation of specified algorithm code is
// available.
func Available(alg string) bool {
	_, ok := algorithms[alg]
	return ok
}

// RegisterAlgorithm registers a function that returns a new instance of the
// given algorithm. This is intended to be called from the init function in
// packages that implement algorithm methods.
func RegisterAlgorithm(alg string, f func() Algorithm) {
	algorithms[alg] = f
}
