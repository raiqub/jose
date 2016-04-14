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

package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/raiqub/jose/jwk"
)

func newECDSAKey(alg string) (*ecdsa.PrivateKey, error) {
	var curve elliptic.Curve
	switch alg {
	case "ES256":
		curve = elliptic.P256()
	case "ES384":
		curve = elliptic.P384()
	case "ES512":
		curve = elliptic.P521()
	default:
		return nil, jwk.UnhandledAlgorithm(alg)
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, ErrorGeneratingKey(err.Error())
	}

	return key, nil
}
