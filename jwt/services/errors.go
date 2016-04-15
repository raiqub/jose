package services

import (
	"fmt"
)

type UnexpectedSigningMethod string

func (e UnexpectedSigningMethod) Error() string {
	return fmt.Sprintf("Unexpected signing method: %s", string(e))
}

type InvalidKeyID struct {
	Value interface{}
}

func (e InvalidKeyID) Error() string {
	return fmt.Sprintf("Invalid key ID: %v", e.Value)
}

type InvalidToken int

func (e InvalidToken) Error() string {
	return "Invalid token"
}
