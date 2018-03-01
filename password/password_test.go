package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandomString(t *testing.T) {
	assert := assert.New(t)

	var result string
	var err error

	result, err = RandomString(0)
	assert.NotNil(err)
	assert.Equal("", result)

	result, err = RandomString(7)
	assert.NotNil(err)
	assert.Equal("", result)

	result, err = RandomString(8)
	assert.Nil(err)
	assert.Equal(8, len(result))

	first, err := RandomString(20)
	assert.Nil(err)
	second, err := RandomString(20)
	assert.Nil(err)
	assert.Equal(20, len(first))
	assert.Equal(20, len(second))
	assert.NotEqual(first, second)
}
