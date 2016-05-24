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
	jwkservices "github.com/raiqub/jose/jwk/services"
	"github.com/raiqub/jose/jws"
	"github.com/raiqub/jose/jwt"
	"github.com/raiqub/tlog"
	"gopkg.in/raiqub/slice.v1"
)

// A Verifier represents a service which provides token decoding and validation.
type Verifier struct {
	issuers []string
	keys    map[string]*Cache
}

// NewVerifier creates a new instance of Verifier service.
func NewVerifier(
	svcJWKSet jwkservices.SetService,
	tracer tlog.Tracer,
	issuers ...string,
) (*Verifier, error) {
	if tracer == nil {
		tracer = tlog.NewTracerNop()
	}

	jwkset, err := svcJWKSet.GetCerts(tracer)
	if err != nil {
		return nil, err
	}

	result := &Verifier{
		issuers,
		make(map[string]*Cache, 0),
	}

	for _, k := range jwkset.Keys {
		rawKey, err := k.Key()
		if err != nil {
			return nil, err
		}

		result.keys[k.ID] = &Cache{k, rawKey}
		tracer.AddEntry(
			tlog.LevelInfo, "jwkset_key_loaded", "JWK set key loaded: "+k.ID,
			0, nil, "Verifier", "NewVerifier")
	}

	return result, nil
}

// Verify specified token and decode it.
func (v *Verifier) Verify(
	rawtoken string,
	header jws.Header,
	payload ClaimsSecure,
) (*jws.SignedToken, error) {
	token, err := jws.DecodeAndValidate(
		rawtoken, header, payload,
		func(header jws.Header) (interface{}, error) {
			var key *Cache
			var ok bool

			if key, ok = v.keys[header.GetID()]; !ok {
				return nil, ErrInvalidKeyID(header.GetID())
			}
			if header.GetAlgorithm() != key.JWK.Algorithm {
				return nil, ErrUnexpectedAlg(header.GetAlgorithm())
			}

			return key.RawKey, nil
		},
	)

	if err != nil {
		return nil, err
	}

	if !token.Validate() {
		return nil, ErrInvalidToken(0)
	}

	if secPayload, ok := token.Payload.(ClaimsSecure); !ok ||
		!slice.String(v.issuers).Exists(secPayload.GetIssuer(), false) {
		return nil, ErrInvalidToken(0)
	}

	return token, nil
}

// VerifyScopes validates client and user scopes when available.
func (v *Verifier) VerifyScopes(
	claims jwt.ClientUserScopes,
	client, user []string,
) bool {
	var scopes []string

	if client != nil && len(client) > 0 {
		scopes = claims.GetScopes()
		if scopes == nil || len(scopes) == 0 {
			return false
		}

		if !slice.String(scopes).
			ExistsAny(client, false) {
			return false
		}
	}

	if user != nil && len(user) > 0 {
		scopes = claims.GetUserScopes()
		if scopes == nil || len(scopes) == 0 {
			return false
		}

		if !slice.String(scopes).
			ExistsAny(user, false) {
			return false
		}
	}

	return true
}
