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

// RBACUser provides stubs for User#Secret and User#IsVerified as RBAC-implementations
// often do not maintain these values as part of their business logic, but instead
// delegate it to their RBAC system.
type RBACUser struct {
}

// Secret stubs User#Secret.
func (user RBACUser) Secret() (secret string) {
	panic("RBACUser#Secret is unimplemented")
}

// IsVerified stubs User#IsVerified.
func (user RBACUser) IsVerified() (ok bool) {
	panic("RBACUser#IsVerifiedis unimplemented")
}
