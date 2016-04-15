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

package jwt

type ErrorGetKey string

func (e ErrorGetKey) Error() string {
	return "Error getting the signing key for token"
}

type ErrorInvalidFormat string

func (e ErrorInvalidFormat) Error() string {
	return "The format of provided token is invalid"
}

type ErrorInvalidSignature string

func (e ErrorInvalidSignature) Error() string {
	return "The token signature is invalid"
}

type ErrorValidation string

func (e ErrorValidation) Error() string {
	return "Error validating JWT token"
}
