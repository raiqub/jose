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

package jwatest

import (
	"testing"

	"github.com/raiqub/jose/jwa"
)

const (
	inputTest = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9`
)

// BenchmarkSigning run parallel signings using specifid algorithm and key.
func BenchmarkSigning(b *testing.B, alg string, key interface{}) {
	method, _ := jwa.New(alg)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := method.Sign(inputTest, key); err != nil {
				b.Fatal(err)
			}
		}
	})
}
