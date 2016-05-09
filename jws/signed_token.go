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

package jws

import (
	"bytes"
	"encoding/base64"
	"strings"

	"github.com/pquerna/ffjson/ffjson"
	"github.com/raiqub/jose/jwa"
	"github.com/raiqub/jose/jwt"
)

// GetKeyFunc defines a function to retrieve a key for specified token.
type GetKeyFunc func(Header) (interface{}, error)

// A SignedToken represents a token encapsuled by JWS.
type SignedToken struct {
	Header  Header
	Payload jwt.Claims
}

// NewSignedToken creates a new instance of SignedToken using default header and
// payload.
func NewSignedToken(alg string) *SignedToken {
	header := RegisteredHeader{
		Algorithm: alg,
	}

	return &SignedToken{
		&header,
		&jwt.CommonClaims{},
	}
}

// DecodeAndValidate decodes an existing token and validates it.
func DecodeAndValidate(
	token string,
	header Header,
	payload jwt.Claims,
	getKey GetKeyFunc,
) (*SignedToken, error) {
	// ===== DECODING =====

	segs := strings.Split(token, ".")
	if len(segs) != 3 {
		return nil, ErrInvalidFormat(token)
	}
	lastDotIdx := strings.LastIndex(token, ".")

	if header == nil {
		header = &RegisteredHeader{}
	}
	if payload == nil {
		payload = &jwt.CommonClaims{}
	}

	b64in, err := base64.RawURLEncoding.DecodeString(segs[0])
	if err != nil {
		return nil, err
	}
	err = ffjson.Unmarshal(b64in, header)
	if err != nil {
		return nil, err
	}

	if err := payload.Decode(segs[1]); err != nil {
		return nil, err
	}

	// ===== VALIDATION =====

	j := &SignedToken{header, payload}
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
	if key, err = getKey(header); err != nil {
		return nil, err
	}

	if err := method.Verify(token[:lastDotIdx], segs[2], key); err != nil {
		return nil, ErrInvalidSignature(token)
	}

	return j, nil
}

// EncodeAndSign creates a string representation of current token and appends a
// signature.
func (t *SignedToken) EncodeAndSign(key interface{}) (string, error) {
	var buf bytes.Buffer

	// HEADER
	b64out := base64.NewEncoder(base64.RawURLEncoding, &buf)
	jout := ffjson.NewEncoder(b64out)
	if err := jout.Encode(t.Header); err != nil {
		return "", err
	}
	b64out.Close()

	buf.WriteString(".")

	// PAYLOAD
	if err := t.Payload.Encode(&buf); err != nil {
		return "", err
	}

	// SIGNATURE
	method, err := jwa.New(t.Header.GetAlgorithm())
	if err != nil {
		return "", err
	}

	sig, err := method.Sign(buf.String(), key)
	if err != nil {
		return "", err
	}

	buf.WriteString(".")
	buf.WriteString(sig)

	return buf.String(), nil
}

// Validate returns whether current token header and payload is valid.
func (t *SignedToken) Validate() bool {
	if !jwa.Available(t.Header.GetAlgorithm()) ||
		t.Payload == nil {
		return false
	}

	return t.Payload.Validate()
}
