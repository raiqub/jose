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

package jws

import (
	"fmt"
)

// An ErrAlgUnavailable represents an error when requested algorithm method is
// not implemented.
type ErrAlgUnavailable string

// Error returns string representation of current instance error.
func (e ErrAlgUnavailable) Error() string {
	return fmt.Sprintf(
		"The specified algorithm method '%s' is unavailable", string(e))
}

// An ErrorGeneratingKey represents an error when generating raw key.
type ErrorGeneratingKey string

// Error returns string representation of current instance error.
func (e ErrorGeneratingKey) Error() string {
	return fmt.Sprintf("Error generating key: %s", string(e))
}

// An ErrHashUnavailable represents an error when requested hash function is not
// implemented to current binary.
type ErrHashUnavailable uint

// Error returns string representation of current instance error.
func (e ErrHashUnavailable) Error() string {
	return fmt.Sprintf(
		"The specified hash function #%d is unavailable", uint(e))
}

// An ErrInvalidKey represents an error when cryptografic key type is not
// supported.
type ErrInvalidKey struct {
	Value interface{}
}

// Error returns string representation of current instance error.
func (e ErrInvalidKey) Error() string {
	return fmt.Sprintf("Unsupported key type: %T", e.Value)
}

// An ErrKeyMustBePEMEncoded represents an error when specified key is a
// byte-array and is not PEM-encoded.
type ErrKeyMustBePEMEncoded int

// Error returns string representation of current instance error.
func (e ErrKeyMustBePEMEncoded) Error() string {
	return "The key should be PEM encoded"
}

// An ErrKeyMustBePKCS1Or8 represents an error when specified key type is not
// PKCS#1 or PKCS#8.
type ErrKeyMustBePKCS1Or8 int

// Error returns string representation of current instance error.
func (e ErrKeyMustBePKCS1Or8) Error() string {
	return "The key should be PKCS#1 or PKCS#8 type"
}

// An ErrSignatureInvalid represents an error when token signature doesn't match
// its content.
type ErrSignatureInvalid int

// Error returns string representation of current instance error.
func (e ErrSignatureInvalid) Error() string {
	return "The provided signature doesn't match input data"
}

// A ErrTooSmallKeySize represents an error when specified key size is less than
// recommended by security experts.
type ErrTooSmallKeySize struct {
	Minimum int
	Actual  int
}

// Error returns string representation of current instance error.
func (e ErrTooSmallKeySize) Error() string {
	return fmt.Sprintf("The key size must be at least %d bits, but got %d",
		e.Minimum, e.Actual)
}
