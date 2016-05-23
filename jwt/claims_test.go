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
	"bytes"
	"testing"
)

const (
	payload = `eyJpc3MiOiJhdXRoLmV4YW1wbGUuY29tIiwiYXVkIjoiMTIzNDU2Nzg5MCIsInN1YiI6Im` +
		`pvaG4uZG9lQGV4YW1wbGUuY29tIiwiZXhwIjoxMzAwODE5MzgwLCJ1c2VyIjp7Im5hbWUiOiJKb2` +
		`huIERvZSIsInNjb3BlcyI6WyJhZG1pbiJdfX0`
	reencodeResult = `eyAiaXNzIjoiYXV0aC5leGFtcGxlLmNvbSIsInN1YiI6ImpvaG4uZG9lQGV4YW1` +
		`wbGUuY29tIiwiYXVkIjoiMTIzNDU2Nzg5MCIsImV4cCI6MTMwMDgxOTM4MCwidXNlciI6eyAibmF` +
		`tZSI6IkpvaG4gRG9lIiwiZW1haWwiOiIiLCJzY29wZXMiOlsiYWRtaW4iXX19`
)

func TestDecodeAndEncode(t *testing.T) {
	var claims CommonClaims
	if err := claims.Decode(payload); err != nil {
		t.Fatalf("Error decoding payload: %v", err)
	}

	if claims.Issuer != "auth.example.com" {
		t.Errorf("Invalid issuer value: %s", claims.Subject)
	}
	if claims.Audience != "1234567890" {
		t.Errorf("Invalid audience value: %s", claims.Audience)
	}
	if claims.Subject != "john.doe@example.com" {
		t.Errorf("Invalid subject value: %s", claims.Subject)
	}
	if claims.ExpireAt.ToInt64() != 1300819380 {
		t.Errorf("Invalid expiration value: %d", claims.ExpireAt.ToInt64())
	}
	if claims.User == nil {
		t.Error("User field should not be null")
	} else {
		usr := claims.User
		if usr.Name != "John Doe" {
			t.Errorf("Invalid user name value: %s", usr.Name)
		}
		if usr.Scopes == nil {
			t.Error("User scopes should not be null")
		}
		if len(usr.Scopes) != 1 {
			t.Errorf("Unexpected user scopes length: %d", len(usr.Scopes))
		}
		if usr.Scopes[0] != "admin" {
			t.Errorf("Invalid user scope value: %s", usr.Scopes[0])
		}
	}

	var buf bytes.Buffer
	if err := claims.Encode(&buf); err != nil {
		t.Errorf("Error encoding claims: %v", err)
	}

	bufStr := buf.String()
	if bufStr != reencodeResult {
		t.Errorf("Unexpected result for claims encoding: %s", bufStr)
	}
}
