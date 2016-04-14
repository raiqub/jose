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

package keygen

import (
	"crypto/rand"
	"crypto/rsa"
)

const (
	// MinimumRSAKeySize defines the minimum key size for RSA keys as
	// recommended by security experts.
	MinimumRSAKeySize = 2048
)

func newRSAKey(alg string, size int) (*rsa.PrivateKey, error) {
	if size < MinimumRSAKeySize {
		return nil, TooSmallKeySize{MinimumRSAKeySize, size}
	}

	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, ErrorGeneratingKey(err.Error())
	}

	return key, nil
}
