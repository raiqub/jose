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

package data

import (
	"errors"

	"github.com/raiqub/jose/jwk"
)

// A SignerMemory represents an in-memory data adapter for Signer service.
type SignerMemory struct {
	keys map[string]*jwk.Key
}

// NewSignerMemory creates a new instance of SignerMemory.
func NewSignerMemory() *SignerMemory {
	return &SignerMemory{
		make(map[string]*jwk.Key, 0),
	}
}

// Add a new key to current data adapter.
func (s *SignerMemory) Add(id string, key *jwk.Key) {
	s.keys[id] = key
}

// GetKey returns a key which matchs specified identifier.
func (s *SignerMemory) GetKey(id string) (*jwk.Key, error) {
	res, ok := s.keys[id]
	if !ok {
		return nil, errors.New("Key not found")
	}

	return res, nil
}
