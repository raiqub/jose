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

import "github.com/raiqub/jose/converters"

func (k *Key) setSymmetric(key []byte) error {
	k.Type = KeyTypeSymmetric
	k.K = converters.Base64.FromBytes(key)
	return nil
}

func (k *Key) getSymmetric() ([]byte, error) {
	data, err := converters.Base64.ToBytes(k.K)
	if err != nil {
		return nil, err
	}

	return data, nil
}
