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

//go:generate ffjson $GOFILE

package jwk

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"time"

	"github.com/raiqub/jose/jws"
)

const (
	// KeyTypeECDSA defines the type code for ECDSA keys.
	KeyTypeECDSA = "EC"

	// KeyTypeRSA defines the type code for RSA keys.
	KeyTypeRSA = "RSA"

	// KeyTypeSymmetric defines the type code for symmetric keys.
	KeyTypeSymmetric = "oct"
)

type (
	// A Set represents a set of keys as defined by JWK specification.
	Set struct {
		Keys []Key `json:"keys"`
	}

	// A Key represents a key as defined by JWK specification.
	Key struct {
		ID        string    `bson:"_id" json:"kid"`
		Type      string    `bson:"kty" json:"kty"`
		Algorithm string    `bson:"alg" json:"alg"`
		Usage     string    `bson:"use" json:"use"`
		NotBefore time.Time `bson:"nbf,omitempty" json:"-"`
		ExpireAt  time.Time `bson:"exp,omitempty" json:"-"`

		// ECDSA

		Curve string `bson:"crv,omitempty" json:"crv,omitempty"`
		X     string `bson:"x,omitempty" json:"x,omitempty"`
		Y     string `bson:"y,omitempty" json:"y,omitempty"`
		D     string `bson:"d,omitempty" json:"-"`

		// 	RSA

		N       string `bson:"n,omitempty" json:"n,omitempty"`
		E       string `bson:"e,omitempty" json:"e,omitempty"`
		PrimeP  string `bson:"p,omitempty" json:"-"`
		PrimeQ  string `bson:"q,omitempty" json:"-"`
		PreDp   string `bson:"dp,omitempty" json:"-"`
		PreDq   string `bson:"dq,omitempty" json:"-"`
		PreQinv string `bson:"qi,omitempty" json:"-"`
		//D       string `bson:"d,omitempty" json:"-"`

		// Symmetric

		K string `bson:"k,omitempty" json:"-"`
	}
)

// GenerateID creates a new identifier for current key.
func (k *Key) GenerateID() error {
	id, err := kidGen()
	if err != nil {
		return err
	}

	k.ID = id
	return nil
}

// IsECDSA returns whether current key type is ECDSA.
func (k *Key) IsECDSA() bool {
	return k.Type == KeyTypeECDSA
}

// IsRSA returns whether current key type is RSA.
func (k *Key) IsRSA() bool {
	return k.Type == KeyTypeRSA
}

// IsSymmetric returns whether current key type is symmetric.
func (k *Key) IsSymmetric() bool {
	return k.Type == KeyTypeSymmetric
}

// Key creates a raw key instance based on current key specification.
func (k *Key) Key() (interface{}, error) {
	switch k.Type {
	case KeyTypeECDSA:
		return k.getECDSA()
	case KeyTypeRSA:
		return k.getRSA()
	case KeyTypeSymmetric:
		return k.getSymmetric()
	default:
		return nil, ErrUnknownType(k.Type)
	}
}

// RemovePrivateFields discards all private information of current key.
func (k *Key) RemovePrivateFields() {
	k.D = ""
	k.PrimeP = ""
	k.PrimeQ = ""
	k.PreDp = ""
	k.PreDq = ""
	k.PreQinv = ""
	k.K = ""
}

// SetKey parses specified raw key and sets current key to match it.
func (k *Key) SetKey(key interface{}, alg jws.Algorithm) error {
	if !alg.Available() {
		return jws.ErrAlgUnavailable(alg)
	}

	var err error
	switch keyCast := key.(type) {
	case *ecdsa.PublicKey:
		err = k.setECDSA(keyCast, nil)
	case *ecdsa.PrivateKey:
		err = k.setECDSA(&keyCast.PublicKey, keyCast)
	case *rsa.PublicKey:
		err = k.setRSA(keyCast, nil)
	case *rsa.PrivateKey:
		err = k.setRSA(&keyCast.PublicKey, keyCast)
	case []byte:
		err = k.setSymmetric(keyCast)
	default:
		return jws.ErrInvalidKey{Value: key}
	}
	if err != nil {
		return err
	}

	switch k.Type {
	case KeyTypeECDSA:
		if alg[:2] != "ES" {
			return ErrIncompatibleAlg{k.Type, alg.String()}
		}
	case KeyTypeRSA:
		if alg[:2] != "RS" && alg[:2] != "PS" {
			return ErrIncompatibleAlg{k.Type, alg.String()}
		}
	case KeyTypeSymmetric:
		if alg[:2] != "HS" {
			return ErrIncompatibleAlg{k.Type, alg.String()}
		}
	}

	if len(k.ID) == 0 {
		if err := k.GenerateID(); err != nil {
			return ErrGenID(err.Error())
		}
	}

	k.Algorithm = alg.String()
	return nil
}

// GenerateKey generates a key of the given algorithm, bit size and life
// duration
func GenerateKey(alg jws.Algorithm, bits, days int) (*Key, error) {
	method, err := alg.New()
	if err != nil {
		return nil, err
	}

	key, err := method.GenerateKey(bits)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	jwkKey := Key{
		Usage:     "sig",
		NotBefore: now,
		ExpireAt:  now.Add(time.Hour * 24 * time.Duration(days)),
	}

	if err := jwkKey.SetKey(key, alg); err != nil {
		return nil, err
	}

	return &jwkKey, nil
}
