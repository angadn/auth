package auth

import "fmt"

// Some handy errors you can use to send out of packages that depend on auth.
var (
	// ErrUnauthorizedUser when User lacks necessary permissions to make a request.
	ErrUnauthorizedUser = fmt.Errorf("user not authorized to make that request")
)

// User is a generic type that requires your application-level Users to implement certain
type User interface {
	ID() string
	Secret() string
	IsVerified() bool
}
