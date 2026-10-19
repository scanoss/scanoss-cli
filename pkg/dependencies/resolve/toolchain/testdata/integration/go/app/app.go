package app

import (
	"example.com/local"
	"github.com/google/uuid"
)

func ID() string {
	return local.Prefix + uuid.NewString()
}
