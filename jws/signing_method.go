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

import "io"

var signingMethods = map[string]func() SigningMethod{}

// SigningMethod defines a template to methods for signing or verifying tokens.
type SigningMethod interface {
	// Verify whether a signature matches the input data.
	Verify(input, signature io.Reader, key interface{}) error

	// Sign generates a signature for input data.
	Sign(input io.Reader, key interface{}) (string, error)

	// Algorithm returns the algorithm code for this method (e.g. 'HS256').
	Algorithm() string
}

// RegisterSigningMethod registers the "alg" name and a factory function for
// signing method.
func RegisterSigningMethod(alg string, f func() SigningMethod) {
	signingMethods[alg] = f
}

// GetSigningMethod gets a signing method from an "alg" string
func GetSigningMethod(alg string) (method SigningMethod) {
	if methodF, ok := signingMethods[alg]; ok {
		method = methodF()
	}
	return
}
