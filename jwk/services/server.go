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
	"net/http"

	"github.com/raiqub/jose/jwk"
	"github.com/raiqub/jose/jwk/adapters"
	"github.com/raiqub/tlog"
	"gopkg.in/raiqub/web.v0"
)

// A SetServer represents a server which provides the key set used for signing or
// encrypting session tokens.
type SetServer struct {
	adpSet adapters.Set
}

// NewSetServer creates a new instance of SetServer.
func NewSetServer(adpSet adapters.Set) *SetServer {
	return &SetServer{
		adpSet,
	}
}

// GetCerts returns entire key set.
func (s *SetServer) GetCerts(tracer tlog.Tracer) (*jwk.Set, *web.JSONError) {
	keys, err := s.adpSet.All()
	if err != nil {
		tracer.AddEntry(
			tlog.LevelError, "query_error", "Error querying for JWK keys",
			http.StatusInternalServerError, err,
			"SetServer", "Set.All")
		jerr := web.NewJSONError().FromError(err).Build()
		return nil, &jerr
	}

	return keys, nil
}

var _ SetService = (*SetServer)(nil)
