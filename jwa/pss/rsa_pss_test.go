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

package pss_test

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/raiqub/jose/jwa"
	"github.com/raiqub/jose/jwa/jwatest"
	_ "github.com/raiqub/jose/jwa/pss"
	"github.com/raiqub/jose/jwa/rsa"
)

const (
	privKeyFile = "../rsa/test/sample_key"
	pubKeyFile  = "../rsa/test/sample_key.pub"
)

var rsaPSSTestData = []struct {
	name        string
	tokenString string
	alg         string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"Basic PS256",
		"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.PPG4xyDVY8ffp4CcxofNmsTDXsrVG2npdQuibLhJbv4ClyPTUtR5giNSvuxo03kB6I8VXVr0Y9X7UxhJVEoJOmULAwRWaUsDnIewQa101cVhMa6iR8X37kfFoiZ6NkS-c7henVkkQWu2HtotkEtQvN5hFlk8IevXXPmvZlhQhwzB1sGzGYnoi1zOfuL98d3BIjUjtlwii5w6gYG2AEEzp7HnHCsb3jIwUPdq86Oe6hIFjtBwduIK90ca4UqzARpcfwxHwVLMpatKask00AgGVI0ysdk0BLMjmLutquD03XbThHScC2C2_Pp4cHWgMzvbgLU2RYYZcZRKr46QeNgz9w",
		"PS256",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"Basic PS384",
		"eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.w7-qqgj97gK4fJsq_DCqdYQiylJjzWONvD0qWWWhqEOFk2P1eDULPnqHRnjgTXoO4HAw4YIWCsZPet7nR3Xxq4ZhMqvKW8b7KlfRTb9cH8zqFvzMmybQ4jv2hKc3bXYqVow3AoR7hN_CWXI3Dv6Kd2X5xhtxRHI6IL39oTVDUQ74LACe-9t4c3QRPuj6Pq1H4FAT2E2kW_0KOc6EQhCLWEhm2Z2__OZskDC8AiPpP8Kv4k2vB7l0IKQu8Pr4RcNBlqJdq8dA5D3hk5TLxP8V5nG1Ib80MOMMqoS3FQvSLyolFX-R_jZ3-zfq6Ebsqr0yEb0AH2CfsECF7935Pa0FKQ",
		"PS384",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"Basic PS512",
		"eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.GX1HWGzFaJevuSLavqqFYaW8_TpvcjQ8KfC5fXiSDzSiT9UD9nB_ikSmDNyDILNdtjZLSvVKfXxZJqCfefxAtiozEDDdJthZ-F0uO4SPFHlGiXszvKeodh7BuTWRI2wL9-ZO4mFa8nq3GMeQAfo9cx11i7nfN8n2YNQ9SHGovG7_T_AvaMZB_jT6jkDHpwGR9mz7x1sycckEo6teLdHRnH_ZdlHlxqknmyTu8Odr5Xh0sJFOL8BepWbbvIIn-P161rRHHiDWFv6nhlHwZnVzjx7HQrWSGb6-s2cdLie9QL_8XaMcUpjLkfOMKkDOfHo6AvpL7Jbwi83Z2ZTHjJWB-A",
		"PS512",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"basic PS256 invalid: foo => bar",
		"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.PPG4xyDVY8ffp4CcxofNmsTDXsrVG2npdQuibLhJbv4ClyPTUtR5giNSvuxo03kB6I8VXVr0Y9X7UxhJVEoJOmULAwRWaUsDnIewQa101cVhMa6iR8X37kfFoiZ6NkS-c7henVkkQWu2HtotkEtQvN5hFlk8IevXXPmvZlhQhwzB1sGzGYnoi1zOfuL98d3BIjUjtlwii5w6gYG2AEEzp7HnHCsb3jIwUPdq86Oe6hIFjtBwduIK90ca4UqzARpcfwxHwVLMpatKask00AgGVI0ysdk0BLMjmLutquD03XbThHScC2C2_Pp4cHWgMzvbgLU2RYYZcZRKr46QeNgz9W",
		"PS256",
		map[string]interface{}{"foo": "bar"},
		false,
	},
}

func TestRSAPSSVerify(t *testing.T) {
	keyPub, _ := ioutil.ReadFile(pubKeyFile)
	keyPrv, _ := ioutil.ReadFile(privKeyFile)

	for i, data := range rsaPSSTestData {
		method, err := jwa.New(data.alg)
		if err != nil {
			t.Errorf("[%s] Error while loading algorithm method: %v",
				data.name, err)
			continue
		}

		lastDotIdx := strings.LastIndex(data.tokenString, ".")
		input := data.tokenString[:lastDotIdx]
		signature := data.tokenString[lastDotIdx+1:]

		key := keyPub
		if i%2 == 0 {
			key = keyPrv
		}
		err = method.Verify(input, signature, key)
		if data.valid && err != nil {
			t.Errorf("[%s] Error while verifying key: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%s] Invalid key passed validation", data.name)
		}
	}
}

func TestRSAPSSSign(t *testing.T) {
	key, _ := ioutil.ReadFile(privKeyFile)

	for _, data := range rsaPSSTestData {
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

		sig, err := method.Sign(input, key)
		if err != nil {
			t.Errorf("[%s] Error signing token: %v", data.name, err)
		}
		if sig == signature {
			t.Errorf(
				"[%s] Signatures shouldn't match\nnew:\n%v\noriginal:\n%v",
				data.name, sig, signature)
		}
	}
}

func TestRSAPSSVerifyWithPreParsedPublicKey(t *testing.T) {
	key, _ := ioutil.ReadFile(pubKeyFile)
	parsedKey, err := rsa.ParseFromPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	testData := rsaPSSTestData[0]
	lastDotIdx := strings.LastIndex(testData.tokenString, ".")
	input := testData.tokenString[:lastDotIdx]
	signature := testData.tokenString[lastDotIdx+1:]
	method, _ := jwa.New(jwa.PS256)

	err = method.Verify(input, signature, parsedKey)
	if err != nil {
		t.Errorf("[%s] Error while verifying key: %v", testData.name, err)
	}
}

func TestRSAPSSWithPreParsedPrivateKey(t *testing.T) {
	key, _ := ioutil.ReadFile(privKeyFile)
	parsedKey, err := rsa.ParseFromPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	testData := rsaPSSTestData[0]
	lastDotIdx := strings.LastIndex(testData.tokenString, ".")
	input := testData.tokenString[:lastDotIdx]
	signature := testData.tokenString[lastDotIdx+1:]
	method, _ := jwa.New(jwa.PS256)

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

func BenchmarkPS256Signing(b *testing.B) {
	key, _ := ioutil.ReadFile(privKeyFile)
	parsedKey, err := rsa.ParseFromPEM(key)
	if err != nil {
		b.Fatal(err)
	}

	jwatest.BenchmarkSigning(b, jwa.PS256, parsedKey)
}

func BenchmarkPS384Signing(b *testing.B) {
	key, _ := ioutil.ReadFile(privKeyFile)
	parsedKey, err := rsa.ParseFromPEM(key)
	if err != nil {
		b.Fatal(err)
	}

	jwatest.BenchmarkSigning(b, jwa.PS384, parsedKey)
}

func BenchmarkPS512Signing(b *testing.B) {
	key, _ := ioutil.ReadFile(privKeyFile)
	parsedKey, err := rsa.ParseFromPEM(key)
	if err != nil {
		b.Fatal(err)
	}

	jwatest.BenchmarkSigning(b, jwa.PS512, parsedKey)
}
