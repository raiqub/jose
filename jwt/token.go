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
	"encoding/base64"
	"strings"
	"time"

	"github.com/pquerna/ffjson/ffjson"
	"github.com/raiqub/jose/jwa"
)

// GetKeyFunc defines a function to retrieve a key for specified token.
type GetKeyFunc func(*Token) (interface{}, error)

// A Token represents a token as defined by JWT specification.
type Token struct {
	Header  TokenHeader
	Payload TokenPayload
}

// NewToken creates a new instance of Token type.
func NewToken(header TokenHeader, payload TokenPayload) *Token {
	return &Token{
		header,
		payload,
	}
}

// NewTokenByAlg creates a new instance of Token type using default header and
// payload types.
func NewTokenByAlg(alg string) *Token {
	header := &Header{
		Type:      JWTHeaderType,
		Algorithm: alg,
	}

	return &Token{
		header,
		&Payload{},
	}
}

// Validate returns whether current token is valid by time being.
func (j *Token) Validate() bool {
	if j.Header.GetType() != JWTHeaderType {
		return false
	}

	now := time.Now().Unix()
	exp := j.Payload.GetExpireAt().Unix()
	nbf := j.Payload.GetNotBefore().Unix()
	iat := j.Payload.GetIssuedAt().Unix()

	// Enforces use of exp, nbf and iat fields
	if exp == 0 || nbf == 0 || iat == 0 {
		return false
	}
	if exp < nbf {
		return false
	}
	if now > exp {
		return false
	}
	if now < nbf {
		return false
	}
	if iat > nbf {
		return false
	}

	return true
}

// DecodeAndValidate decodes an existing token and validates it.
func DecodeAndValidate(
	token string,
	header TokenHeader,
	payload TokenPayload,
	getKey GetKeyFunc,
) (*Token, error) {
	// ===== DECODING =====

	segs := strings.Split(token, ".")
	if len(segs) != 3 {
		return nil, ErrInvalidFormat(token)
	}
	lastDotIdx := strings.LastIndex(token, ".")

	if header == nil {
		header = &Header{}
	}
	if payload == nil {
		payload = &Payload{}
	}

	b64in, err := base64.RawURLEncoding.DecodeString(segs[0])
	if err != nil {
		return nil, err
	}
	err = ffjson.Unmarshal(b64in, header)
	if err != nil {
		return nil, err
	}

	b64in, err = base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		return nil, err
	}
	err = ffjson.Unmarshal(b64in, payload)
	if err != nil {
		return nil, err
	}

	// ===== VALIDATION =====

	j := &Token{header, payload}
	if !j.Validate() {
		return nil, ErrInvalidToken(token)
	}

	method, err := jwa.New(j.Header.GetAlgorithm())
	if err != nil {
		return nil, err
	}

	var key interface{}
	if getKey == nil {
		return nil, ErrGetKey(token)
	}
	if key, err = getKey(j); err != nil {
		return nil, err
	}

	if err := method.Verify(token[:lastDotIdx], segs[2], key); err != nil {
		return nil, ErrInvalidSignature(token)
	}

	return j, nil
}

// Encode creates a string representation of current token.
func (j *Token) Encode() string {
	return j.encode().String()
}

func (j *Token) encode() *bytes.Buffer {
	var buf bytes.Buffer

	b64out := base64.NewEncoder(base64.RawURLEncoding, &buf)
	jout := ffjson.NewEncoder(b64out)
	jout.Encode(j.Header)
	b64out.Close()

	buf.WriteString(".")

	b64out = base64.NewEncoder(base64.RawURLEncoding, &buf)
	jout = ffjson.NewEncoder(b64out)
	jout.Encode(j.Payload)
	b64out.Close()

	return &buf
}

// EncodeAndSign creates a string representation of current token and appends a
// signature.
func (j *Token) EncodeAndSign(key interface{}) (string, error) {
	encbuf := j.encode()
	method, err := jwa.New(j.Header.GetAlgorithm())
	if err != nil {
		return "", err
	}

	sig, err := method.Sign(encbuf.String(), key)
	if err != nil {
		return "", err
	}

	encbuf.WriteString(".")
	encbuf.WriteString(sig)

	return encbuf.String(), nil
}
