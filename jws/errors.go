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

// An ErrGetKey represents an error when was unable to retrieve token signing
// key.
type ErrGetKey string

// Error returns string representation of current instance error.
func (e ErrGetKey) Error() string {
	return "Error getting the signing key for token"
}

// An ErrInvalidFormat represents an error when token format is invalid.
type ErrInvalidFormat string

// Error returns string representation of current instance error.
func (e ErrInvalidFormat) Error() string {
	return "The format of provided token is invalid"
}

// An ErrInvalidSignature represents an error when token signature could not be
// validated.
type ErrInvalidSignature string

// Error returns string representation of current instance error.
func (e ErrInvalidSignature) Error() string {
	return "The token signature is invalid"
}

// An ErrInvalidToken represents an error when a token is not valid by time
// being.
type ErrInvalidToken string

// Error returns string representation of current instance error.
func (e ErrInvalidToken) Error() string {
	return "Error validating JWT token"
}
