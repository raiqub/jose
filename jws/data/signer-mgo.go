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
	"github.com/raiqub/jose/jwk"
	"gopkg.in/mgo.v2"
)

// A SignerMongo represents a MongoDB data adapter for Signer service.
type SignerMongo struct {
	col *mgo.Collection
}

// NewSignerMongo creates a new instance of SignerMongo.
func NewSignerMongo(col *mgo.Collection) *SignerMongo {
	return &SignerMongo{
		col,
	}
}

// GetKey returns a key which matchs specified identifier.
func (s *SignerMongo) GetKey(id string) (*jwk.Key, error) {
	var dbKey jwk.Key
	if err := s.col.
		FindId(id).
		One(&dbKey); err != nil {
		return nil, err
	}

	return &dbKey, nil
}
