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

package jwk

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/raiqub/jose/jwa"
	_ "github.com/raiqub/jose/jwa/hmac"
	_ "github.com/raiqub/jose/jwa/pkcs1"
)

const (
	// Examples from RFC 7520

	// Elliptic Curve P-521 Public Key
	ecdsaPublicKey = `{
     "kty": "EC",
     "kid": "bilbo.baggins@hobbiton.example",
     "use": "sig",
     "crv": "P-521",
     "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9
         A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
     "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy
         SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
   }`
	// Elliptic Curve P-521 Private Key
	ecdsaPrivateKey = `{
     "kty": "EC",
     "kid": "bilbo.baggins@hobbiton.example",
     "use": "sig",
     "crv": "P-521",
     "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9
         A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
     "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy
         SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
     "d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb
         KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"
   }`

	// RSA 2048-Bit Public Key
	rsaPublicKey = `{
     "kty": "RSA",
     "kid": "bilbo.baggins@hobbiton.example",
     "use": "sig",
     "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT
         -O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV
         wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-
         oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde
         3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC
         LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g
         HdrNP5zw",
     "e": "AQAB"
   }`
	// RSA 2048-Bit Private Key
	rsaPrivateKey = `{
     "kty": "RSA",
     "kid": "bilbo.baggins@hobbiton.example",
     "use": "sig",
     "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT
         -O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV
         wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-
         oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde
         3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC
         LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g
         HdrNP5zw",
     "e": "AQAB",
     "d": "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e
         iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld
         Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b
         MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU
         6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj
         d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc
         OpBrQzwQ",
     "p": "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR
         aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG
         peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8
         bUq0k",
     "q": "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT
         8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an
         V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0
         s7pFc",
     "dp": "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q
         1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn
         -RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX
         59ehik",
     "dq": "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr
         AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK
         bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK
         T1cYF8",
     "qi": "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N
         ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh
         jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP
         z8aaI4"
   }`

	// HMAC SHA-256 Symmetric Key
	symKey = `{
     "kty": "oct",
     "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
     "use": "sig",
     "alg": "HS256",
     "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
   }`

	symEncKey = `{
     "kty": "oct",
     "kid": "1e571774-2e08-40da-8308-e8d68773842d",
     "use": "enc",
     "alg": "A256GCM",
     "k": "AAPapAv4LbFbiVawEjagUBluYqN5rhna-8nuldDvOx8"
   }`

	kid1 = "bilbo.baggins@hobbiton.example"
	kid2 = "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
	use  = "sig"
	rsaE = "AQAB"

	payload = `SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH` +
		`lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk` +
		`b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm` +
		`UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4`
	payloadDecoded = `It’s a dangerous business, Frodo, going out your door. ` +
		`You step onto the road, and if you don't keep your feet, there’s no ` +
		`knowing where you might be swept off to.`
	rsaHeader = `eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX` +
		`hhbXBsZSJ9`
	rsaSignature = `MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmK` +
		`ZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4J` +
		`IwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8w` +
		`W1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluP` +
		`xUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_f` +
		`cIe8u9ipH84ogoree7vjbU5y18kDquDg`
	symHeader = `eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW` +
		`VlZjMxNGJjNzAzNyJ9`
	symSignature = `s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0`
)

func TestPayloadDecoding(t *testing.T) {
	buf, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal("Error decoding test payload")
	}

	if payloadDecoded != string(buf) {
		t.Error("Unexpected value decoding test payload")
	}
}

func TestDecodeECDSAPublicKey(t *testing.T) {
	key := testDecodeKey(ecdsaPublicKey, "ECDSA public", t)
	if !key.IsECDSA() {
		t.Errorf("Decoded key should be ECDSA")
	}
}

func TestDecodeECDSAPrivateKey(t *testing.T) {
	key := testDecodeKey(ecdsaPrivateKey, "ECDSA private", t)
	if !key.IsECDSA() {
		t.Errorf("Decoded key should be ECDSA")
	}
}

func TestDecodeRSAPublicKey(t *testing.T) {
	key := testDecodeKey(rsaPublicKey, "RSA public", t)
	if !key.IsRSA() {
		t.Errorf("Decoded key should be RSA")
	}
}

func TestDecodeRSAPrivateKey(t *testing.T) {
	key := testDecodeKey(rsaPrivateKey, "RSA private", t)
	if !key.IsRSA() {
		t.Errorf("Decoded key should be RSA")
	}
}

func TestDecodeSymmetricKey(t *testing.T) {
	key := testDecodeKey(symKey, "Symmetric", t)
	if !key.IsSymmetric() {
		t.Error("Decoded key should be symmetric")
	}
}

func testDecodeKey(input, name string, t *testing.T) *Key {
	// Remove characters added for readability and formatting
	input = strings.Replace(input, "\n", "", -1)
	input = strings.Replace(input, " ", "", -1)

	var key Key
	if err := json.Unmarshal([]byte(input), &key); err != nil {
		t.Fatalf("Error decoding %s key: %v", name, err)
	}
	if key.Usage != use {
		t.Errorf("Invalid key usage: %s", key.Usage)
	}
	if key.IsRSA() || key.IsECDSA() {
		if key.ID != kid1 {
			t.Errorf("Invalid key identifier: %s", key.ID)
		}
	} else if key.IsSymmetric() {
		if key.ID != kid2 {
			t.Errorf("Invalid key identifier: %s", key.ID)
		}
	}
	if key.IsRSA() && key.E != rsaE {
		t.Errorf("Invalid exponent value for RSA key: %s", key.E)
	}
	if _, err := key.Key(); err != nil {
		t.Error("Error creating raw key from decoded key")
	}

	return &key
}

func TestSigningRSA(t *testing.T) {
	testSigning("RSA signing", rsaHeader, rsaPrivateKey, jwa.RS256, rsaSignature, t)
}

func TestSigningSymmetric(t *testing.T) {
	testSigning("HMAC signing", symHeader, symKey, jwa.HS256, symSignature, t)
}

func testSigning(name, header, encKey, algName, signature string, t *testing.T) {
	input := header + "." + payload
	key := testDecodeKey(encKey, name, t)
	sigKey, _ := key.Key()

	alg, err := jwa.New(algName)
	if err != nil {
		t.Fatalf("Error loading algorithm: %v", err)
	}

	sig, err := alg.Sign(input, sigKey)
	if err != nil {
		t.Fatalf("Error signing input: %v", err)
	}
	if sig != signature {
		t.Error("Unexpected signature was generated")
	}
}
