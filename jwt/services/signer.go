package services

import (
	"time"

	"github.com/raiqub/jose/jwk"
	"github.com/raiqub/jose/jwt"
	"gopkg.in/mgo.v2"
)

type Signer struct {
	col    *mgo.Collection
	config Config
	keys   map[string]*Cache
}

func NewSigner(config Config, col *mgo.Collection) (*Signer, error) {
	var dbKey jwk.Key
	if err := col.
		FindId(config.SignKeyId).
		One(&dbKey); err != nil {
		return nil, err
	}
	rawKey, err := dbKey.Key()
	if err != nil {
		return nil, err
	}

	return &Signer{
		col,
		config,
		map[string]*Cache{
			dbKey.ID: {dbKey, rawKey},
		},
	}, nil
}

func (s *Signer) Create(payload jwt.TokenPayload) (string, error) {
	now := time.Now()
	signKey := s.keys[s.config.SignKeyId]

	payload.SetIssuer(s.config.Issuer)
	payload.SetExpireAt(now.Add(s.config.Duration))
	payload.SetNotBefore(now)
	payload.SetIssuedAt(now)

	header := &jwt.Header{
		ID:        s.config.SignKeyId,
		Type:      jwt.JWTHeaderType,
		Algorithm: signKey.JWK.Algorithm,
		JWKSetURL: s.config.SetURL,
	}

	token := jwt.NewToken(header, payload)
	out, err := token.EncodeAndSign(signKey.RawKey)
	if err != nil {
		return "", err
	}

	return out, nil
}
