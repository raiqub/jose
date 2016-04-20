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

package jws_test

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/raiqub/jose/jws"
)

var ecdsaTestData = []struct {
	name        string
	privateKey  string
	publicKey   string
	tokenString string
	alg         string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"Basic ES256",
		"test/ec256-private.pem",
		"test/ec256-public.pem",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ",
		"ES256",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"Basic ES384",
		"test/ec384-private.pem",
		"test/ec384-public.pem",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJmb28iOiJiYXIifQ.ngAfKMbJUh0WWubSIYe5GMsA-aHNKwFbJk_wq3lq23aPp8H2anb1rRILIzVR0gUf4a8WzDtrzmiikuPWyCS6CN4-PwdgTk-5nehC7JXqlaBZU05p3toM3nWCwm_LXcld",
		"ES384",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"Basic ES512",
		"test/ec512-private.pem",
		"test/ec512-public.pem",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJmb28iOiJiYXIifQ.AAU0TvGQOcdg2OvrwY73NHKgfk26UDekh9Prz-L_iWuTBIBqOFCWwwLsRiHB1JOddfKAls5do1W0jR_F30JpVd-6AJeTjGKA4C1A1H6gIKwRY0o_tFDIydZCl_lMBMeG5VNFAjO86-WCSKwc3hqaGkq1MugPRq_qrF9AVbuEB4JPLyL5",
		"ES512",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"basic ES256 invalid: foo => bar",
		"test/ec256-private.pem",
		"test/ec256-public.pem",
		"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.MEQCIHoSJnmGlPaVQDqacx_2XlXEhhqtWceVopjomc2PJLtdAiAUTeGPoNYxZw0z8mgOnnIcjoxRuNDVZvybRZF3wR1l8W",
		"ES256",
		map[string]interface{}{"foo": "bar"},
		false,
	},
}

func TestECDSAVerify(t *testing.T) {
	for _, data := range ecdsaTestData {
		method, err := jws.NewAlgorithm(data.alg).New()
		if err != nil {
			t.Errorf("[%s] Error while loading algorithm method: %v",
				data.name, err)
			continue
		}

		key, _ := ioutil.ReadFile(data.publicKey)
		lastDotIdx := strings.LastIndex(data.tokenString, ".")
		input := data.tokenString[:lastDotIdx]
		signature := data.tokenString[lastDotIdx+1:]

		err = method.Verify(input, signature, key)
		if data.valid && err != nil {
			t.Errorf("[%s] Error while verifying key: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%s] Invalid key passed validation", data.name)
		}
	}
}

func TestECDSASign(t *testing.T) {
	for _, data := range ecdsaTestData {
		if !data.valid {
			continue
		}

		method, err := jws.NewAlgorithm(data.alg).New()
		if err != nil {
			t.Errorf("[%s] Error while loading algorithm method: %v",
				data.name, err)
			continue
		}

		key, _ := ioutil.ReadFile(data.privateKey)
		lastDotIdx := strings.LastIndex(data.tokenString, ".")
		input := data.tokenString[:lastDotIdx]
		signature := data.tokenString[lastDotIdx+1:]

		sig, err := method.Sign(input, key)
		if err != nil {
			t.Errorf("[%v] Error signing token: %v", data.name, err)
		}
		if sig == signature {
			t.Errorf(
				"[%v] Identical signatures\nbefore:\n%v\nafter:\n%v",
				data.name, signature, sig)
		}
	}
}

func TestECDSAVerifyWithPreParsedPublicKey(t *testing.T) {
	key, _ := ioutil.ReadFile("test/ec256-public.pem")
	parsedKey, err := jws.ParseECDSAFromPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	testData := ecdsaTestData[0]
	lastDotIdx := strings.LastIndex(testData.tokenString, ".")
	input := testData.tokenString[:lastDotIdx]
	signature := testData.tokenString[lastDotIdx+1:]
	method, _ := jws.ES256.New()

	err = method.Verify(input, signature, parsedKey)
	if err != nil {
		t.Errorf("[%s] Error while verifying key: %v", testData.name, err)
	}
}

func TestECDSAWithPreParsedPrivateKey(t *testing.T) {
	key, _ := ioutil.ReadFile("test/ec256-private.pem")
	parsedKey, err := jws.ParseECDSAFromPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	testData := ecdsaTestData[0]
	lastDotIdx := strings.LastIndex(testData.tokenString, ".")
	input := testData.tokenString[:lastDotIdx]
	signature := testData.tokenString[lastDotIdx+1:]
	method, _ := jws.ES256.New()

	sig, err := method.Sign(input, parsedKey)
	if err != nil {
		t.Errorf("[%s] Error signing token: %v", testData.name, err)
	}
	if sig == signature {
		t.Errorf(
			"[%s] Identical signatures.\nbefore:\n%v\nafter:\n%v",
			testData.name, signature, sig)
	}
}

func TestECDSAKeyParsing(t *testing.T) {
	key, _ := ioutil.ReadFile("test/ec256-private.pem")
	pubKey, _ := ioutil.ReadFile("test/ec512-public.pem")
	badKey := []byte("All your base are belong to key")

	if _, e := jws.ParseECDSAFromPEM(key); e != nil {
		t.Errorf("Failed to parse valid private key: %v", e)
	}

	if _, e := jws.ParseECDSAFromPEM(pubKey); e != nil {
		t.Errorf("Failed to parse valid public key: %v", e)
	}

	if k, e := jws.ParseECDSAFromPEM(badKey); e == nil {
		t.Errorf("Parsed invalid key as valid private key: %v", k)
	}
}

func BenchmarkES256Signing(b *testing.B) {
	key, _ := ioutil.ReadFile("test/ec256-private.pem")
	parsedKey, err := jws.ParseECDSAFromPEM(key)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkSigning(b, jws.ES256, parsedKey)
}

func BenchmarkES384Signing(b *testing.B) {
	key, _ := ioutil.ReadFile("test/ec384-private.pem")
	parsedKey, err := jws.ParseECDSAFromPEM(key)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkSigning(b, jws.ES384, parsedKey)
}

func BenchmarkES512Signing(b *testing.B) {
	key, _ := ioutil.ReadFile("test/ec512-private.pem")
	parsedKey, err := jws.ParseECDSAFromPEM(key)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkSigning(b, jws.ES512, parsedKey)
}
