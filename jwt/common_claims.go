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
	"gopkg.in/raiqub/slice.v1"
)

// A CommonClaims set represents a JSON object whose members are the claims
// conveyed by the JWT.
type CommonClaims struct {
	ID        string      `json:"jti,omitempty"`
	Issuer    string      `json:"iss,omitempty"`
	Subject   string      `json:"sub,omitempty"`
	Audience  string      `json:"aud,omitempty"`
	ExpireAt  UnixTime    `json:"exp"`
	NotBefore UnixTime    `json:"nbf,omitempty"`
	IssuedAt  UnixTime    `json:"iat,omitempty"`
	Scopes    []string    `json:"scopes,omitempty"`
	User      *UserClaims `json:"user,omitempty"`
}

// A UserClaims represents the user claims set embedded on main claims set.
type UserClaims struct {
	Name    string   `json:"name"`
	Email   string   `json:"email"`
	Scopes  []string `json:"scopes"`
	Country string   `json:"country,omitempty"`
	Tags    []string `json:"tags,omitempty"`
}

// GetAudience returns the recipients that the JWT is intended for.
func (p *CommonClaims) GetAudience() string {
	return p.Audience
}

// GetExpireAt returns the token expiration date.
func (p *CommonClaims) GetExpireAt() time.Time {
	return p.ExpireAt.ToTime()
}

// GetIssuedAt returns the token issue date.
func (p *CommonClaims) GetIssuedAt() time.Time {
	return p.IssuedAt.ToTime()
}

// GetIssuer returns the token issuer.
func (p *CommonClaims) GetIssuer() string {
	return p.Issuer
}

// GetNotBefore returns the minimal date required to use current token.
func (p *CommonClaims) GetNotBefore() time.Time {
	return p.NotBefore.ToTime()
}

// GetSubject returns the principal that is the subject of the JWT.
func (p *CommonClaims) GetSubject() string {
	return p.Subject
}

// HasClientScopes determines whether any of specified client scopes exists on current
// instance.
func (p *CommonClaims) HasClientScopes(scopes ...string) bool {
	if scopes == nil || len(scopes) == 0 {
		return true
	}

	if p.Scopes == nil || len(p.Scopes) == 0 {
		return false
	}

	return slice.String(p.Scopes).
		ExistsAny(scopes, false)
}

// HasUserScopes determines whether any of specified user scopes exists on current
// instance.
func (p *CommonClaims) HasUserScopes(scopes ...string) bool {
	if scopes == nil || len(scopes) == 0 {
		return true
	}

	if p.User == nil || p.User.Scopes == nil || len(p.User.Scopes) == 0 {
		return false
	}

	return slice.String(p.User.Scopes).
		ExistsAny(scopes, false)
}

// SetExpireAt defines the token expiration date.
func (p *CommonClaims) SetExpireAt(dt time.Time) {
	p.ExpireAt = NewUnixTime(dt)
}

// SetIssuedAt defines the token issue date.
func (p *CommonClaims) SetIssuedAt(dt time.Time) {
	p.IssuedAt = NewUnixTime(dt)
}

// SetIssuer defines the token issuer.
func (p *CommonClaims) SetIssuer(issuer string) {
	p.Issuer = issuer
}

// SetNotBefore defines the minimal date required to use current token.
func (p *CommonClaims) SetNotBefore(dt time.Time) {
	p.NotBefore = NewUnixTime(dt)
}

// Decode specified encoded token to current instance.
func (p *CommonClaims) Decode(input string) error {
	b64in, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		return err
	}
	err = ffjson.Unmarshal(b64in, p)
	if err != nil {
		return err
	}

	return nil
}

// Encode current instance to specified writer.
func (p *CommonClaims) Encode(w io.Writer) error {
	b64out := base64.NewEncoder(base64.RawURLEncoding, w)
	jout := ffjson.NewEncoder(b64out)
	if err := jout.Encode(p); err != nil {
		return err
	}

	b64out.Close()
	return nil
}

// Validate returns whether current claims are valid.
func (p *CommonClaims) Validate() bool {
	now := time.Now().Unix()
	exp := p.ExpireAt.ToInt64()
	nbf := p.NotBefore.ToInt64()
	iat := p.IssuedAt.ToInt64()

	// Enforce use of exp claim
	if exp <= 0 || now > exp {
		return false
	}

	// Reject invalid values
	if nbf < 0 || iat < 0 ||
		exp < nbf || exp < iat {
		return false
	}
	if nbf > 0 && nbf > now {
		return false
	}
	if nbf > 0 && iat > 0 && iat > nbf {
		return false
	}

	return true
}

var _ Claims = (*CommonClaims)(nil)
