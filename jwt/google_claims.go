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

//go:generate ffjson $GOFILE

package jwt

import (
	"encoding/base64"
	"io"
	"time"

	"github.com/pquerna/ffjson/ffjson"
)

// A GoogleClaims represents a JSON object from Google ID Tokens.
type GoogleClaims struct {
	Issuer          string   `json:"iss"`
	Subject         string   `json:"sub"`
	AuthorizedParty string   `json:"azp"`
	Audience        string   `json:"aud"`
	IssuedAt        UnixTime `json:"iat"`
	ExpireAt        UnixTime `json:"exp"`

	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Locale        string `json:"locale,omitempty"`
	HostedDomain  string `json:"hd,omitempty"`
}

// GetAudience returns the recipients that the JWT is intended for.
func (gc *GoogleClaims) GetAudience() string {
	return gc.Audience
}

// GetExpireAt returns the token expiration date.
func (gc *GoogleClaims) GetExpireAt() time.Time {
	return gc.ExpireAt.ToTime()
}

// GetIssuedAt returns the token issue date.
func (gc *GoogleClaims) GetIssuedAt() time.Time {
	return gc.IssuedAt.ToTime()
}

// GetIssuer returns the token issuer.
func (gc *GoogleClaims) GetIssuer() string {
	return gc.Issuer
}

// GetNotBefore returns zero.
func (*GoogleClaims) GetNotBefore() time.Time {
	return time.Unix(0, 0)
}

// GetSubject returns the principal that is the subject of the JWT.
func (gc *GoogleClaims) GetSubject() string {
	return gc.Subject
}

// SetExpireAt defines the token expiration date.
func (gc *GoogleClaims) SetExpireAt(dt time.Time) {
	gc.ExpireAt = NewUnixTime(dt)
}

// SetIssuedAt defines the token issue date.
func (gc *GoogleClaims) SetIssuedAt(dt time.Time) {
	gc.IssuedAt = NewUnixTime(dt)
}

// SetIssuer defines the token issuer.
func (gc *GoogleClaims) SetIssuer(issuer string) {
	gc.Issuer = issuer
}

// SetNotBefore does nothing.
func (*GoogleClaims) SetNotBefore(dt time.Time) {}

// Decode specified encoded token to current instance.
func (gc *GoogleClaims) Decode(input string) error {
	b64in, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		return err
	}
	err = ffjson.Unmarshal(b64in, gc)
	if err != nil {
		return err
	}

	return nil
}

// Encode current instance to specified writer.
func (gc *GoogleClaims) Encode(w io.Writer) error {
	b64out := base64.NewEncoder(base64.RawURLEncoding, w)
	jout := ffjson.NewEncoder(b64out)
	if err := jout.Encode(gc); err != nil {
		return err
	}

	b64out.Close()
	return nil
}

// Validate returns whether current claims are valid.
func (gc *GoogleClaims) Validate() bool {
	now := time.Now().Unix()
	exp := gc.ExpireAt.ToInt64()
	iat := gc.IssuedAt.ToInt64()

	// Enforce use of exp and iat claims
	if exp <= 0 || iat <= 0 || now > exp {
		return false
	}

	// Reject invalid values
	if exp < iat {
		return false
	}

	return true
}

var _ Claims = (*GoogleClaims)(nil)
