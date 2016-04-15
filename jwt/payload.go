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
	"time"
)

type Payload struct {
	Issuer    string       `json:"iss"`
	Subject   string       `json:"sub,omitempty"`
	Audience  string       `json:"aud"`
	ExpireAt  UnixTime     `json:"exp"`
	NotBefore UnixTime     `json:"nbf"`
	IssuedAt  UnixTime     `json:"iat"`
	Scopes    []string     `json:"scopes"`
	User      *PayloadUser `json:"user,omitempty"`
}

type PayloadUser struct {
	Name    string   `json:"name"`
	Email   string   `json:"email"`
	Scopes  []string `json:"scopes"`
	Country string   `json:"country"`
	Tags    []string `json:"tags"`
}

func (p *Payload) GetExpireAt() time.Time {
	return p.ExpireAt.ToTime()
}

func (p *Payload) GetIssuedAt() time.Time {
	return p.IssuedAt.ToTime()
}

func (p *Payload) GetIssuer() string {
	return p.Issuer
}

func (p *Payload) GetNotBefore() time.Time {
	return p.NotBefore.ToTime()
}

func (p *Payload) GetScopes() []string {
	return p.Scopes
}

func (p *Payload) GetUserScopes() []string {
	if p.User == nil {
		return nil
	}

	return p.User.Scopes
}

func (p *Payload) SetExpireAt(dt time.Time) {
	p.ExpireAt = NewUnixTime(dt)
}

func (p *Payload) SetIssuedAt(dt time.Time) {
	p.IssuedAt = NewUnixTime(dt)
}

func (p *Payload) SetIssuer(issuer string) {
	p.Issuer = issuer
}

func (p *Payload) SetNotBefore(dt time.Time) {
	p.NotBefore = NewUnixTime(dt)
}

var _ TokenPayload = (*Payload)(nil)
