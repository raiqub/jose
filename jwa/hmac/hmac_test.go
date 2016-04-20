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

package hmac_test

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/raiqub/jose/jwa"
	"github.com/raiqub/jose/jwa/jwatest"

	_ "github.com/raiqub/jose/jwa/hmac"
)

var hmacTestData = []struct {
	name        string
	tokenString string
	alg         string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"web sample",
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		"HS256",
		map[string]interface{}{"iss": "joe", "exp": 1300819380, "http://example.com/is_root": true},
		true,
	},
	{
		"HS384",
		"eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0.KWZEuOD5lbBxZ34g7F-SlVLAQ_r5KApWNWlZIIMyQVz5Zs58a7XdNzj5_0EcNoOy",
		"HS384",
		map[string]interface{}{"iss": "joe", "exp": 1300819380, "http://example.com/is_root": true},
		true,
	},
	{
		"HS512",
		"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0.CN7YijRX6Aw1n2jyI2Id1w90ja-DEMYiWixhYCyHnrZ1VfJRaFQz1bEbjjA5Fn4CLYaUG432dEYmSbS4Saokmw",
		"HS512",
		map[string]interface{}{"iss": "joe", "exp": 1300819380, "http://example.com/is_root": true},
		true,
	},
	{
		"web sample: invalid",
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXo",
		"HS256",
		map[string]interface{}{"iss": "joe", "exp": 1300819380, "http://example.com/is_root": true},
		false,
	},
}

// Sample data from http://tools.ietf.org/html/draft-jones-json-web-signature-04#appendix-A.1
var hmacTestKey, _ = ioutil.ReadFile("test/hmacTestKey")

func TestHMACVerify(t *testing.T) {
	for _, data := range hmacTestData {
		method, err := jwa.New(data.alg)
		if err != nil {
			t.Errorf("[%s] Error while loading algorithm method: %v",
				data.name, err)
			continue
		}

		lastDotIdx := strings.LastIndex(data.tokenString, ".")
		input := data.tokenString[:lastDotIdx]
		signature := data.tokenString[lastDotIdx+1:]

		err = method.Verify(input, signature, hmacTestKey)
		if data.valid && err != nil {
			t.Errorf("[%s] Error while verifying key: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%s] Invalid key passed validation", data.name)
		}
	}
}

func TestHMACSign(t *testing.T) {
	for _, data := range hmacTestData {
		if !data.valid {
			continue
		}

		method, err := jwa.New(data.alg)
		if err != nil {
			t.Errorf("[%s] Error while loading algorithm method: %v",
				data.name, err)
			continue
		}

		lastDotIdx := strings.LastIndex(data.tokenString, ".")
		input := data.tokenString[:lastDotIdx]
		signature := data.tokenString[lastDotIdx+1:]

		sig, err := method.Sign(input, hmacTestKey)
		if err != nil {
			t.Errorf("[%s] Error signing token: %v", data.name, err)
		}
		if sig != signature {
			t.Errorf(
				"[%s] Incorrect signature.\nwas:\n%v\nexpecting:\n%v",
				data.name, sig, signature)
		}
	}
}

func BenchmarkHS256Signing(b *testing.B) {
	jwatest.BenchmarkSigning(b, jwa.HS256, hmacTestKey)
}

func BenchmarkHS384Signing(b *testing.B) {
	jwatest.BenchmarkSigning(b, jwa.HS384, hmacTestKey)
}

func BenchmarkHS512Signing(b *testing.B) {
	jwatest.BenchmarkSigning(b, jwa.HS512, hmacTestKey)
}
