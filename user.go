package auth

import "fmt"

// Some handy errors you can use to send out of packages that depend on auth.
var (
	// ErrUnauthorizedUser when User lacks necessary permissions to make a request.
	ErrUnauthorizedUser = fmt.Errorf("user not authorized to make that request")
)

// User is a generic type that requires your application-level Users to implement certain
type User interface {
	GetID() string
	GetSecret() string
	GetIsVerified() bool
}

// RBACUser provides stubs for User#Secret and User#IsVerified as RBAC-implementations
// often do not maintain these values as part of their business logic, but instead
// delegate it to their RBAC system.
type RBACUser struct {
}

// GetSecret stubs User#Secret.
func (user RBACUser) GetSecret() (secret string) {
	secret = "RBACUser#GetSecret is unimplemented"
	return
}

// GetIsVerified stubs User#GetIsVerified.
func (user RBACUser) GetIsVerified() (ok bool) {
	ok = true
	return
}
