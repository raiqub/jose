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
	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/raiqub/jose/converters"
)

func (k *Key) setECDSA(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey) error {
	cname, err := curveName(pub.Curve)
	if err != nil {
		return err
	}

	size := curveSize(pub.Curve)

	k.Type = KeyTypeECDSA
	k.Curve = cname
	k.X = converters.Base64.FromBigInt(pub.X, size)
	k.Y = converters.Base64.FromBigInt(pub.Y, size)

	if priv != nil {
		k.D = converters.Base64.FromBigInt(priv.D, 0)
	}

	return nil
}

func (k *Key) getECDSA() (interface{}, error) {
	curve, err := curveFromName(k.Curve)
	if err != nil {
		return nil, err
	}

	x, err := converters.Base64.ToBigInt(k.X)
	if err != nil {
		return nil, err
	}
	y, err := converters.Base64.ToBigInt(k.Y)
	if err != nil {
		return nil, err
	}

	pub := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	var key interface{}
	if len(k.D) > 0 {
		d, err := converters.Base64.ToBigInt(k.D)
		if err != nil {
			return nil, err
		}
		key = &ecdsa.PrivateKey{
			PublicKey: pub,
			D:         d,
		}
	} else {
		key = &pub
	}

	return key, nil
}

func curveFromName(cname string) (elliptic.Curve, error) {
	switch cname {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, UnsupportedEllipticCurve(0)
	}
}

// Get JOSE name of curve
func curveName(crv elliptic.Curve) (string, error) {
	switch crv {
	case elliptic.P256():
		return "P-256", nil
	case elliptic.P384():
		return "P-384", nil
	case elliptic.P521():
		return "P-521", nil
	default:
		return "", UnsupportedEllipticCurve(0)
	}
}

// Get size of curve in bytes
func curveSize(crv elliptic.Curve) int {
	bits := crv.Params().BitSize

	div := bits / 8
	mod := bits % 8

	if mod == 0 {
		return div
	}

	return div + 1
}
