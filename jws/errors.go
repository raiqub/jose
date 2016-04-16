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

// An ErrHashUnavailable represents an error when requested hash function is not
// implemented to current binary.
type ErrHashUnavailable string

// Error returns string representation of current instance error.
func (e ErrHashUnavailable) Error() string {
	return fmt.Sprintf(
		"The specified hash function is not available to current binary: %s",
		string(e))
}

// An ErrInvalidKey represents an error when cryptografic key type is not
// supported.
type ErrInvalidKey int

// Error returns string representation of current instance error.
func (e ErrInvalidKey) Error() string {
	return "The key provided is invalid"
}

// An ErrSignatureInvalid represents an error when token signature doesn't match
// its content.
type ErrSignatureInvalid int

// Error returns string representation of current instance error.
func (e ErrSignatureInvalid) Error() string {
	return "The provided signature doesn't match input data"
}
