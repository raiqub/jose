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

	"github.com/pquerna/ffjson/ffjson"
	"github.com/raiqub/jose/jwk"
	"gopkg.in/raiqub/web.v0"
)

// A SetClient represents a client for a service that provides the key set used
// for signing or encrypting session tokens.
type SetClient struct {
	url string
}

// NewSetClient creates a new instace of a client for key set service.
func NewSetClient(url string) *SetClient {
	return &SetClient{
		url,
	}
}

// GetCerts returns the key set from the service.
func (c *SetClient) GetCerts() (*jwk.Set, *web.JSONError) {
	resp, err := http.Get(c.url)
	if err != nil {
		jerr := web.NewJSONError().FromError(err).Build()
		return nil, &jerr
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var jerr web.JSONError
		if err := ffjson.NewDecoder().
			DecodeReader(resp.Body, &jerr); err != nil {
			jerr = web.NewJSONError().FromError(err).Build()
		}

		return nil, &jerr
	}

	var keyset jwk.Set
	if err := ffjson.NewDecoder().
		DecodeReader(resp.Body, &keyset); err != nil {
		jerr := web.NewJSONError().FromError(err).Build()
		return nil, &jerr
	}

	return &keyset, nil
}

var _ SetService = (*SetClient)(nil)
