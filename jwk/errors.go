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

// An ErrGenID represents an error when could not generate a new identifier for
// a JWK key.
type ErrGenID string

// Error returns string representation of current instance error.
func (e ErrGenID) Error() string {
	return fmt.Sprintf("Error generating key identifier: %s", string(e))
}

// An ErrIncompatibleAlg represents an error when key type and algorithm are not
// compatible with each other.
type ErrIncompatibleAlg struct {
	Type      string
	Algorithm string
}

// Error returns string representation of current instance error.
func (e ErrIncompatibleAlg) Error() string {
	return fmt.Sprintf(
		"The algorithm '%s' is not compatible with '%s' key type",
		e.Algorithm, e.Type)
}

// An ErrUnknownType represents an error when the type specified for JWK key is
// not supported by current implementation.
type ErrUnknownType string

// Error returns string representation of current instance error.
func (e ErrUnknownType) Error() string {
	return fmt.Sprintf("Unknown JSON Web Key type: %s", string(e))
}

// An ErrUnsupportedEC represents an error when specified curve for ECDSA key is
// not supported by current implementation.
type ErrUnsupportedEC string

// Error returns string representation of current instance error.
func (e ErrUnsupportedEC) Error() string {
	return fmt.Sprintf("Unsupported elliptic curve: %s", string(e))
}
