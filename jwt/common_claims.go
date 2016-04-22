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

// A CommonClaims set represents a JSON object whose members are the claims
// conveyed by the JWT.
type CommonClaims struct {
	ID        string      `json:"jti,omitempty"`
	Issuer    string      `json:"iss"`
	Subject   string      `json:"sub,omitempty"`
	Audience  string      `json:"aud"`
	ExpireAt  UnixTime    `json:"exp"`
	NotBefore UnixTime    `json:"nbf"`
	IssuedAt  UnixTime    `json:"iat"`
	Scopes    []string    `json:"scopes"`
	User      *UserClaims `json:"user,omitempty"`
}

// A UserClaims represents the user claims set embedded on main claims set.
type UserClaims struct {
	Name    string   `json:"name"`
	Email   string   `json:"email"`
	Scopes  []string `json:"scopes"`
	Country string   `json:"country"`
	Tags    []string `json:"tags"`
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

// GetScopes returns the scopes allowed to client.
func (p *CommonClaims) GetScopes() []string {
	return p.Scopes
}

// GetSubject returns the principal that is the subject of the JWT.
func (p *CommonClaims) GetSubject() string {
	return p.Subject
}

// GetUserScopes returns the scopes allowed to user.
func (p *CommonClaims) GetUserScopes() []string {
	if p.User == nil {
		return nil
	}

	return p.User.Scopes
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

var _ Claims = (*CommonClaims)(nil)
