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

package adapters

import (
	"errors"

	"github.com/raiqub/jose/jwk"
)

// ErrKeyNotFound defines an error when requested key was not found.
var ErrKeyNotFound = errors.New("Key not found")

// A SetMemory represents an in-memory data adapter for JWK key set.
type SetMemory struct {
	keys map[string]jwk.Key
}

// NewSetMemory creates a new instance of SetMemory.
func NewSetMemory() *SetMemory {
	return &SetMemory{
		make(map[string]jwk.Key, 0),
	}
}

// Add a new key to current data adapter.
func (s *SetMemory) Add(key jwk.Key) error {
	s.keys[key.ID] = key
	return nil
}

// All returns all keys.
func (s *SetMemory) All() (*jwk.Set, error) {
	var keys []jwk.Key
	for _, k := range s.keys {
		keys = append(keys, k)
	}

	return &jwk.Set{
		Keys: keys,
	}, nil
}

// ByID returns a key by its identifier.
func (s *SetMemory) ByID(id string) (*jwk.Key, error) {
	res, ok := s.keys[id]
	if !ok {
		return nil, errors.New("Key not found")
	}

	return &res, nil
}

var _ Set = (*SetMemory)(nil)
