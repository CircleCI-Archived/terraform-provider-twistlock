package password

import (
	crypto "crypto/rand"
	"fmt"
	"math"
	"math/big"
	"math/rand"
)

const DefaultCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"$%^&*(){} <>?/\\#';:"

func newRand() (*rand.Rand, error) {
	max := big.NewInt(math.MaxInt64)
	seed, err := crypto.Int(crypto.Reader, max)
	if err != nil {
		return nil, err
	}

	return rand.New(rand.NewSource(seed.Int64())), nil
}

// RandomString returns a string of comprised of `length` randomly chosen
// characters from DefaultCharset.
//
// length must be at least 8
func RandomString(length uint) (string, error) {
	if length < 8 {
		return "", fmt.Errorf("length must be at least 8 characters")
	}

	r, err := newRand()
	if err != nil {
		return "", err
	}

	chars := make([]byte, length)
	for i := uint(0); i < length; i++ {
		chars[i] = DefaultCharset[r.Intn(len(DefaultCharset))]
	}
	return string(chars), nil
}
