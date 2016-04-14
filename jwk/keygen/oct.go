package keygen

import "crypto/rand"

const (
	// MinimumOCTKeySize defines the minimum recommended key size for symmetric
	// keys.
	MinimumOCTKeySize = 512
)

func newSymKey(alg string, size int) ([]byte, error) {
	if size < MinimumOCTKeySize {
		return nil, TooSmallKeySize{MinimumOCTKeySize, size}
	}

	buf := make([]byte, size/8)
	if _, err := rand.Read(buf); err != nil {
		return nil, ErrorGeneratingKey(err.Error())
	}

	return buf, nil
}
