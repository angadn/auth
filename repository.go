package auth

import (
	"context"
)

// Repository is the interface for your application's repository to implement.
type Repository interface {
	FindAuthUser(ctx context.Context, id string) (User, bool, error)
}
