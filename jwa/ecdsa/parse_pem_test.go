/*
 * Copyright 2012 Dave Grijalva
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

package ecdsa_test

import (
	"io/ioutil"
	"testing"

	"github.com/raiqub/jose/jwa/ecdsa"
)

func TestECDSAKeyParsing(t *testing.T) {
	key, _ := ioutil.ReadFile("test/ec256-private.pem")
	pubKey, _ := ioutil.ReadFile("test/ec512-public.pem")
	badKey := []byte("All your base are belong to key")

	if _, e := ecdsa.ParseFromPEM(key); e != nil {
		t.Errorf("Failed to parse valid private key: %v", e)
	}

	if _, e := ecdsa.ParseFromPEM(pubKey); e != nil {
		t.Errorf("Failed to parse valid public key: %v", e)
	}

	if k, e := ecdsa.ParseFromPEM(badKey); e == nil {
		t.Errorf("Parsed invalid key as valid private key: %v", k)
	}
}
