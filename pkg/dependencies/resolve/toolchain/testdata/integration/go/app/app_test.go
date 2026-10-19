package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestID(t *testing.T) {
	assert.NotEqual(t, ID(), ID())
}
