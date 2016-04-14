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

package converters

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"strconv"
)

type b64 int

// Base64 provides a converter to encode/decode values to/from string
// representation of Base-64 URL-encoded without padding characters.
var Base64 = b64(0)

// StringBigInt convert a big.Int to Base64 URL encoded string and optionally
// sets number zero-padding. Set it to 0 to disable padding.
func (b64) FromBigInt(b *big.Int, size int) string {
	data := b.Bytes()
	if size > 0 {
		data = bytesPadding(data, size)
	}

	return base64.RawURLEncoding.EncodeToString(data)
}

func (b64) FromBytes(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func (b64) FromInt(n int, trim bool) string {
	var data []byte
	switch strconv.IntSize {
	case 32:
		data = make([]byte, 4)
		binary.BigEndian.PutUint32(data, uint32(n))
	case 64:
		data = make([]byte, 8)
		binary.BigEndian.PutUint64(data, uint64(n))
	default:
		panic(UnsupportedIntegerSize(strconv.IntSize))
	}

	if trim {
		data = bytes.TrimLeft(data, "\x00")
	}

	return base64.RawURLEncoding.EncodeToString(data)
}

func (b64) ToBigInt(src string) (*big.Int, error) {
	data, err := base64.RawURLEncoding.DecodeString(src)
	if err != nil {
		return nil, err
	}

	return (&big.Int{}).SetBytes(data), nil
}

func (b64) ToBytes(src string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(src)
}

func (b64) ToInt(src string) (int, error) {
	data, err := base64.RawURLEncoding.DecodeString(src)
	if err != nil {
		return 0, err
	}

	switch strconv.IntSize {
	case 32:
		if len(data) < 4 {
			data = bytesPadding(data, 4)
		}
		return int(binary.BigEndian.Uint32(data)), nil
	case 64:
		if len(data) < 8 {
			data = bytesPadding(data, 8)
		}
		return int(binary.BigEndian.Uint64(data)), nil
	default:
		panic(UnsupportedIntegerSize(strconv.IntSize))
	}
}

func bytesPadding(data []byte, size int) []byte {
	diff := size - len(data)
	pad := make([]byte, diff, len(data)+diff)
	pad = append(pad, data...)
	return pad
}
