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

package services

import (
	"github.com/raiqub/jose/jwk"
	"github.com/raiqub/tlog"
	"gopkg.in/raiqub/web.v0"
)

// A SetService defines an interface for a service that provides the key set
// used for signing or encrypting session tokens.
type SetService interface {
	GetCerts(tlog.Tracer) (*jwk.Set, *web.JSONError)
}
