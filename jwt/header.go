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

//go:generate ffjson $GOFILE

package jwt

import "github.com/raiqub/jose/jwa"

const (
	// JWTHeaderType defines the type name for JWT header.
	JWTHeaderType = "JWT"
)

// A Header represents the header part of a token as defined by JWT
// specification.
type Header struct {
	ID        string `json:"kid,omitempty"`
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	JWKSetURL string `json:"jku,omitempty"`
}

// NewHeader creates a new instance of Header type.
func NewHeader(alg string) *Header {
	return &Header{
		Type:      JWTHeaderType,
		Algorithm: alg,
	}
}

// GetID returns the identifier of the key used to sign current token.
func (h *Header) GetID() string {
	return h.ID
}

// GetType returns the type of current token.
func (h *Header) GetType() string {
	return h.Type
}

// GetAlgorithm returns the algorithm used to sign current token.
func (h *Header) GetAlgorithm() jwa.Algorithm {
	return jwa.NewAlgorithm(h.Algorithm)
}

// GetJWKSetURL returns a URL to retrieve the key used to sign current token.
func (h *Header) GetJWKSetURL() string {
	return h.JWKSetURL
}

var _ TokenHeader = (*Header)(nil)
