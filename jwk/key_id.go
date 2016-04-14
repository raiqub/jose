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

package jwk

import (
	"crypto/rand"
	"io"

	"github.com/raiqub/jose/converters"
)

var kidGen = DefaultKeyIDGenerator

// The KeyIDGenerator type is an adapter to allow to set custom identifiers
// generator for keys.
type KeyIDGenerator func() (string, error)

// DefaultKeyIDGenerator defines the default implementation for generating key
// identifiers.
func DefaultKeyIDGenerator() (string, error) {
	const keyIDSize = 16
	kidBytes := make([]byte, keyIDSize)

	if _, err := io.ReadFull(rand.Reader, kidBytes); err != nil {
		return "", err
	}

	return converters.Base64.FromBytes(kidBytes), nil
}

// SetIDGenerator defines a custom generator for key identifiers.
func SetIDGenerator(f KeyIDGenerator) {
	kidGen = f
}
