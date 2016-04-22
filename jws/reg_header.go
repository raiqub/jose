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

package jws

const (
	// JWTHeaderType defines the type name for JWT header.
	JWTHeaderType = "JOSE"
)

// A RegisteredHeader represents the JOSE header with all registered parameter
// names.
type RegisteredHeader struct {
	ID          string   `json:"kid,omitempty"`
	Type        string   `json:"typ,omitempty"`
	ContentType string   `json:"cty,omitempty"`
	Algorithm   string   `json:"alg"`
	JWKSetURL   string   `json:"jku,omitempty"`
	JWK         string   `json:"jwk,omitempty"`
	X509URL     string   `json:"x5u,omitempty"`
	X509Chain   string   `json:"x5c,omitempty"`
	X509SHA1    string   `json:"x5t,omitempty"`
	X509SHA256  string   `json:"x5t#S256,omitempty"`
	Critical    []string `json:"crit,omitempty"`
}

// NewHeader creates a new instance of Header type.
func NewHeader(alg string) *RegisteredHeader {
	return &RegisteredHeader{
		Type:      JWTHeaderType,
		Algorithm: alg,
	}
}

// GetID returns the identifier of the key used to sign current token.
func (h *RegisteredHeader) GetID() string {
	return h.ID
}

// GetAlgorithm returns the algorithm used to sign current token.
func (h *RegisteredHeader) GetAlgorithm() string {
	return h.Algorithm
}

// GetJWKSetURL returns a URL to retrieve the key used to sign current token.
func (h *RegisteredHeader) GetJWKSetURL() string {
	return h.JWKSetURL
}

var _ Header = (*RegisteredHeader)(nil)
