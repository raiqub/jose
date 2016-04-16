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
	"github.com/raiqub/jose/jwk"
	"github.com/raiqub/jose/jws"
)

type GetKeyFunc func(*Token) (interface{}, error)

// A JWT represents a JWT object.
type Token struct {
	Header  TokenHeader
	Payload TokenPayload
}

func NewToken(header TokenHeader, payload TokenPayload) *Token {
	return &Token{
		header,
		payload,
	}
}

func NewTokenByAlg(method jws.SigningMethod) *Token {
	header := &Header{
		Type:      JWTHeaderType,
		Algorithm: method.Algorithm(),
	}

	return &Token{
		header,
		&Payload{},
	}
}

func (j *Token) Validate() bool {
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

func DecodeAndValidate(
	token string,
	header TokenHeader,
	payload TokenPayload,
	getKey GetKeyFunc,
) (*Token, error) {
	// ===== DECODING =====

	segs := strings.Split(token, ".")
	if len(segs) != 3 {
		return nil, ErrorInvalidFormat(token)
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
		return nil, ErrorValidation(token)
	}

	method := jws.GetSigningMethod(j.Header.GetAlgorithm())
	if method == nil {
		return nil, jwk.UnhandledAlgorithm(j.Header.GetAlgorithm())
	}

	var key interface{}
	if getKey == nil {
		return nil, ErrorGetKey(token)
	}
	if key, err = getKey(j); err != nil {
		return nil, err
	}

	if err := method.Verify(
		strings.NewReader(token[:lastDotIdx]),
		strings.NewReader(segs[2]),
		key,
	); err != nil {
		return nil, ErrorInvalidSignature(token)
	}

	return j, nil
}

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

func (j *Token) EncodeAndSign(key interface{}) (string, error) {
	encbuf := j.encode()
	method := jws.GetSigningMethod(j.Header.GetAlgorithm())
	if method == nil {
		return "", jwk.UnhandledAlgorithm(j.Header.GetAlgorithm())
	}

	sig, err := method.Sign(encbuf, key)
	if err != nil {
		return "", err
	}

	encbuf.WriteString(".")
	encbuf.WriteString(sig)

	return encbuf.String(), nil
}
