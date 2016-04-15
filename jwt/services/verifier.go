package services

import (
	"errors"

	jwkservices "github.com/raiqub/jose/jwk/services"
	"github.com/raiqub/jose/jwt"
	"gopkg.in/raiqub/dot.v1"
)

type Verifier struct {
	issuer string
	keys   map[string]*Cache
}

func NewVerifier(
	svcJWKSet jwkservices.SetService,
	issuer string,
) (*Verifier, error) {
	jwkset, jerr := svcJWKSet.GetCerts()
	if jerr != nil {
		// TODO proper error type
		return nil, errors.New(jerr.Type + ": " + jerr.Message)
	}

	result := &Verifier{
		issuer,
		make(map[string]*Cache, 0),
	}

	for _, k := range jwkset.Keys {
		rawKey, err := k.Key()
		if err != nil {
			return nil, err
		}

		result.keys[k.ID] = &Cache{k, rawKey}
		// TODO log loaded key
		//fmt.Println("[Verifier] Loaded key:", k.ID)
	}
	// TODO log loaded keys
	//fmt.Printf("[Verifier] Loaded %d keys\n", len(result.keys))

	return result, nil
}

func (v *Verifier) Verify(rawtoken string) (*jwt.Token, error) {
	token, err := jwt.DecodeAndValidate(
		rawtoken, nil, nil,
		func(token *jwt.Token) (interface{}, error) {
			var key *Cache
			var ok bool

			if key, ok = v.keys[token.Header.GetID()]; !ok {
				return nil, InvalidKeyID{token.Header.GetID()}
			}
			if token.Header.GetAlgorithm() != key.JWK.Algorithm {
				return nil, UnexpectedSigningMethod(token.Header.GetAlgorithm())
			}

			return key.RawKey, nil
		},
	)

	if err != nil {
		return nil, err
	}

	if token.Payload.GetIssuer() != v.issuer {
		return nil, InvalidToken(0)
	}

	return token, nil
}

func (v *Verifier) VerifyScopes(
	payload jwt.TokenPayload,
	client, user []string,
) bool {
	var scopes []string

	if client != nil && len(client) > 0 {
		scopes = payload.GetScopes()
		if scopes == nil || len(scopes) == 0 {
			return false
		}

		if !dot.StringSlice(scopes).
			ExistsAny(client, false) {
			return false
		}
	}

	if user != nil && len(user) > 0 {
		scopes = payload.GetUserScopes()
		if scopes == nil || len(scopes) == 0 {
			return false
		}

		if !dot.StringSlice(scopes).
			ExistsAny(user, false) {
			return false
		}
	}

	return true
}
