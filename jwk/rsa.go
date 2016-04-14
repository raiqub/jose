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
	"crypto/rsa"
	"math/big"

	"github.com/raiqub/jose/converters"
)

func (k *Key) setRSA(pub *rsa.PublicKey, priv *rsa.PrivateKey) error {
	k.Type = KeyTypeRSA
	k.N = converters.Base64.FromBigInt(pub.N, 0)
	k.E = converters.Base64.FromInt(pub.E, true)

	if priv != nil {
		k.D = converters.Base64.FromBigInt(priv.D, 0)
		k.PrimeP = converters.Base64.FromBigInt(priv.Primes[0], 0)
		k.PrimeQ = converters.Base64.FromBigInt(priv.Primes[1], 0)

		if priv.Precomputed.Dp != nil {
			k.PreDp = converters.Base64.FromBigInt(
				priv.Precomputed.Dp, 0)
		}
		if priv.Precomputed.Dq != nil {
			k.PreDq = converters.Base64.FromBigInt(
				priv.Precomputed.Dq, 0)
		}
		if priv.Precomputed.Qinv != nil {
			k.PreQinv = converters.Base64.FromBigInt(
				priv.Precomputed.Qinv, 0)
		}
	}

	return nil
}

func (k *Key) getRSA() (interface{}, error) {
	n, err := converters.Base64.ToBigInt(k.N)
	if err != nil {
		return nil, err
	}
	e, err := converters.Base64.ToInt(k.E)
	if err != nil {
		return nil, err
	}

	pub := rsa.PublicKey{
		N: n,
		E: e,
	}

	var key interface{}
	if len(k.D) > 0 && len(k.PrimeP) > 0 && len(k.PrimeQ) > 0 {
		d, err := converters.Base64.ToBigInt(k.D)
		if err != nil {
			return nil, err
		}
		p, err := converters.Base64.ToBigInt(k.PrimeP)
		if err != nil {
			return nil, err
		}
		q, err := converters.Base64.ToBigInt(k.PrimeQ)
		if err != nil {
			return nil, err
		}

		priv := &rsa.PrivateKey{
			PublicKey: pub,
			D:         d,
			Primes:    []*big.Int{p, q},
		}

		if len(k.PreDp) > 0 {
			dp, err := converters.Base64.ToBigInt(k.PreDp)
			if err != nil {
				return nil, err
			}
			priv.Precomputed.Dp = dp
		}
		if len(k.PreDq) > 0 {
			dq, err := converters.Base64.ToBigInt(k.PreDq)
			if err != nil {
				return nil, err
			}
			priv.Precomputed.Dq = dq
		}
		if len(k.PreQinv) > 0 {
			qi, err := converters.Base64.ToBigInt(k.PreQinv)
			if err != nil {
				return nil, err
			}
			priv.Precomputed.Qinv = qi
		}
		key = priv
	} else {
		key = &pub
	}

	return key, nil
}
