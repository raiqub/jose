package keygen

import (
	"fmt"
)

// An ErrorGeneratingKey represents an error when generating raw key.
type ErrorGeneratingKey string

// Error returns string representation of current instance error.
func (e ErrorGeneratingKey) Error() string {
	return fmt.Sprintf("Error generating key: %s", string(e))
}

// A TooSmallKeySize represents an error when specified key size is less than
// recommended by security experts.
type TooSmallKeySize struct {
	Minimum int
	Actual  int
}

// Error returns string representation of current instance error.
func (e TooSmallKeySize) Error() string {
	return fmt.Sprintf("The key size must be at least %d bits, but got %d",
		e.Minimum, e.Actual)
}
