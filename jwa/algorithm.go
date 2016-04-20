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

// SigningMethod defines a template to methods for signing or verifying tokens.
type SigningMethod interface {
	// Verify whether a signature matches the input data.
	Verify(input, signature string, key interface{}) error

	// Sign generates a signature for input data.
	Sign(input string, key interface{}) (string, error)

	// GenerateKey generates a key pair of the given bit size, or for symmetric
	// algorithms generates a single key of the given bit size.
	GenerateKey(bits int) (interface{}, error)
}

// An Algorithm represents a cryptographic algorithm to digitally sign or create
// a MAC of the token header and payload.
type Algorithm string

// List of available algorithms as defined by JWA specification.
// Ref: https://tools.ietf.org/html/rfc7518#section-3.1.
const (
	// HS256 defines an HMAC algorithm using SHA-256.
	HS256 = Algorithm("HS256")

	// HS384 defines an HMAC algorithm using SHA-384.
	HS384 = Algorithm("HS384")

	// HS384 defines an HMAC algorithm using SHA-512.
	HS512 = Algorithm("HS512")

	// RS256 defines an RSASSA-PKCS1-v1_5 algorithm using SHA-256.
	RS256 = Algorithm("RS256")

	// RS384 defines an RSASSA-PKCS1-v1_5 algorithm using SHA-384.
	RS384 = Algorithm("RS384")

	// RS512 defines an RSASSA-PKCS1-v1_5 algorithm using SHA-512.
	RS512 = Algorithm("RS512")

	// ES256 defines an ECDSA algorithm using P-256 and SHA-256.
	ES256 = Algorithm("ES256")

	// ES384 defines an ECDSA algorithm using P-384 and SHA-384.
	ES384 = Algorithm("ES384")

	// ES384 defines an ECDSA algorithm using P-521 and SHA-512.
	ES512 = Algorithm("ES512")

	// ES256 defines an RSASSA-PSS algorithm using SHA-256 and MGF1 with
	// SHA-256.
	PS256 = Algorithm("PS256")

	// ES384 defines an RSASSA-PSS algorithm using SHA-384 and MGF1 with
	// SHA-384.
	PS384 = Algorithm("PS384")

	// ES384 defines an RSASSA-PSS algorithm using SHA-512 and MGF1 with
	// SHA-512.
	PS512 = Algorithm("PS512")
)

var methods = map[string]func() SigningMethod{}

// NewAlgorithm creates an Algorithm instance from algorithm name.
func NewAlgorithm(alg string) Algorithm {
	return Algorithm(alg)
}

// New returns a new SigningMethod for signing or verifying tokens.
// Returns ErrAlgUnavailable when the algorithm method is not implemented.
func (a Algorithm) New() (SigningMethod, error) {
	if m, ok := methods[string(a)]; ok {
		return m(), nil
	}

	return nil, ErrAlgUnavailable(string(a))
}

// Available reports whether an implementation to current Algorithm is
// available.
func (a Algorithm) Available() bool {
	_, ok := methods[string(a)]
	return ok
}

// String returns the string representation of current algorithm.
func (a Algorithm) String() string {
	return string(a)
}

// RegisterAlgorithm registers a function that returns a new instance of the
// given algorithm. This is intended to be called from the init function in
// packages that implement algorithm methods.
func RegisterAlgorithm(alg Algorithm, f func() SigningMethod) {
	methods[string(alg)] = f
}
