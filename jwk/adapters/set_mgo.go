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
	"time"

	"github.com/raiqub/jose/jwk"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// A SetMongo represents a MongoDB data adapter for JWK key set.
type SetMongo struct {
	col *mgo.Collection
}

// NewSetMongo creates a new instance of SetMongo.
func NewSetMongo(col *mgo.Collection) *SetMongo {
	return &SetMongo{
		col,
	}
}

// All returns all keys.
func (s *SetMongo) All() (*jwk.Set, error) {
	var keys []jwk.Key
	err := s.col.Find(bson.M{
		"nbf": bson.M{"$lte": time.Now()},
		"exp": bson.M{"$gt": time.Now()},
		"kty": bson.M{"$in": []string{jwk.KeyTypeECDSA, jwk.KeyTypeRSA}},
	}).Select(bson.M{
		"kty": 1, "alg": 1, "use": 1,
		"crv": 1, "x": 1, "y": 1,
		"n": 1, "e": 1,
	}).All(&keys)
	if err != nil {
		return nil, err
	}

	return &jwk.Set{
		Keys: keys,
	}, nil
}

// ByID returns a key by its identifier.
func (s *SetMongo) ByID(id string) (*jwk.Key, error) {
	var dbKey jwk.Key
	if err := s.col.
		FindId(id).
		One(&dbKey); err != nil {
		return nil, err
	}

	return &dbKey, nil
}

var _ Set = (*SetMongo)(nil)
