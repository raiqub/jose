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

import "github.com/raiqub/jose/jwk"

// A Set represents a data adapter for JWK key set.
type Set interface {
	// All returns all keys.
	All() (*jwk.Set, error)

	// ByID returns a key by its identifier.
	ByID(string) (*jwk.Key, error)
}
