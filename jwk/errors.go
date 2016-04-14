/*
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

package jwk

import (
	"fmt"
)

// An ErrorGeneratingID represents an error when could not generate a new
// identifier for a JWK key.
type ErrorGeneratingID string

// Error returns string representation of current instance error.
func (e ErrorGeneratingID) Error() string {
	return fmt.Sprintf("Error generating key identifier: %s", string(e))
}

// An IncompatibleAlgorithm represents an error when key type and algorithm are
// not compatible with each other.
type IncompatibleAlgorithm struct {
	Type      string
	Algorithm string
}

// Error returns string representation of current instance error.
func (e IncompatibleAlgorithm) Error() string {
	return fmt.Sprintf(
		"The algorithm '%s' is not compatible with '%s' key type",
		e.Algorithm, e.Type)
}

// An UnhandledAlgorithm represents an error when specified algorithm is not
// supported by current implementation.
type UnhandledAlgorithm string

// Error returns string representation of current instance error.
func (e UnhandledAlgorithm) Error() string {
	return fmt.Sprintf("Unhandled algorithm: %s", string(e))
}

// An UnsupportedEllipticCurve represents an error when specified curve for
// ECDSA key is not supported by current implementation.
type UnsupportedEllipticCurve int

// Error returns string representation of current instance error.
func (e UnsupportedEllipticCurve) Error() string {
	return "Unsupported or unknown elliptic curve"
}

// An UnknownJWKType represents an error when the type specified for JWK key is
// supported by current implementation.
type UnknownJWKType string

// Error returns string representation of current instance error.
func (e UnknownJWKType) Error() string {
	return fmt.Sprintf("Unknown JSON Web Key type: %s", string(e))
}

// An UnknownKeyType represents an error when specified raw key has a type that
// is unsupported by current implementation.
type UnknownKeyType struct {
	Value interface{}
}

// Error returns string representation of current instance error.
func (e UnknownKeyType) Error() string {
	return fmt.Sprintf("Unknown key type: %T", e.Value)
}
