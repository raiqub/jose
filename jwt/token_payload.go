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

package jwt

import (
	"encoding/json"
	"time"
)

type TokenPayload interface {
	GetExpireAt() time.Time
	GetIssuedAt() time.Time
	GetIssuer() string
	GetNotBefore() time.Time
	GetScopes() []string
	GetUserScopes() []string

	SetExpireAt(time.Time)
	SetIssuedAt(time.Time)
	SetIssuer(string)
	SetNotBefore(time.Time)

	json.Marshaler
	json.Unmarshaler
}
