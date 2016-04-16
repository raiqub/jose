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

package converters_test

import (
	"encoding/base64"
	"io/ioutil"
	"runtime"
	"strings"
	"testing"
)

const b64encSample = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func TestDecoderBug(t *testing.T) {
	const target = "go1.5"

	reader := strings.NewReader(b64encSample)
	b64reader := base64.NewDecoder(base64.RawURLEncoding, reader)
	out, err := ioutil.ReadAll(b64reader)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}

	b64out := base64.RawURLEncoding.EncodeToString(out)

	if runtime.Version()[:len(target)] == target {
		if b64out == b64encSample {
			t.Error("Base64 decoder is expected to be buggy on Go 1.5")
		}
	} else {
		if b64out != b64encSample {
			t.Errorf(
				"Error Base64-decoding sample: expected '%s' got '%s'",
				b64encSample, b64out)
		}
	}
}
