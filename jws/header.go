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

package jws

import "encoding/json"

// A Header represents the JOSE Header which describes the digital signature or
// MAC applied to the JWS Protected Header and the JWS Payload and optionally
// additional properties of the JWS.
type Header interface {
	GetID() string
	GetAlgorithm() string
	GetJWKSetURL() string

	json.Marshaler
	json.Unmarshaler
}
