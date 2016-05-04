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
	"github.com/raiqub/tlog"
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
func (c *SetClient) GetCerts(tracer tlog.Tracer) (*jwk.Set, error) {
	if tracer == nil {
		tracer = tlog.NewTracerNop()
	}

	resp, err := http.Get(c.url)
	if err != nil {
		tracer.AddEntry(
			tlog.LevelError, "http_error", "HTTP protocol error",
			http.StatusServiceUnavailable, err,
			"SetClient", "GetCerts", "http.Get")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var tEntry tlog.TracerEntry
		if err := ffjson.NewDecoder().
			DecodeReader(resp.Body, &tEntry); err != nil {
			tracer.AddEntry(
				tlog.LevelError, "invalid_body", "Invalid body content",
				http.StatusServiceUnavailable, err,
				"SetClient", "GetCerts", "status>=400", "DecodeReader")
			return nil, err
		}

		tracer.AddEntry(
			tlog.LevelWarn, "response_error", "Service returned error",
			http.StatusServiceUnavailable, &tEntry,
			"SetClient", "GetCerts", "status>=400")
		return nil, &tEntry
	}

	var keyset jwk.Set
	if err := ffjson.NewDecoder().
		DecodeReader(resp.Body, &keyset); err != nil {
		tracer.AddEntry(
			tlog.LevelError, "invalid_body", "Invalid body content",
			http.StatusServiceUnavailable, err,
			"SetClient", "GetCerts", "status<400", "DecodeReader")
		return nil, err
	}

	return &keyset, nil
}

var _ SetService = (*SetClient)(nil)
