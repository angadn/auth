package auth

import (
	"context"
	"fmt"
	"log"
)

// Option to configure different behaviour for Session#Auth.
type Option int

const (
	// IgnoreUnverified and pass Auth.
	IgnoreUnverified = Option(1)
)

// Key is a non-simple type for keys in the context.Context operations by Sessions.
type Key string

const (
	// UserKey for storing auth.Auth with context.WithValue(...).
	UserKey = Key("user")
)

var (
	repo      Repository
	isRepoSet bool
)

// WithRepository configures the UserRepository implementation that `auth` will refer.
func WithRepository(r Repository) {
	repo = r
	isRepoSet = true
}

// Session for an authenticated User.
type Session interface {
	Auth() (context.Context, error)
	Cancel()
}

var (
	// ErrMissingUserCredentials when auth information isn't present in message.
	ErrMissingUserCredentials = fmt.Errorf("missing user credentials")

	// ErrInvalidUserCredentials when ID, Secret doesn't match that in the database.
	ErrInvalidUserCredentials = fmt.Errorf("invalid user credentials")

	// ErrUserNotVerified when user hasn't verified email ID, phone, etc.
	ErrUserNotVerified = fmt.Errorf("user not verified")
)

// baseSession holds our reusable auth-logic.
type baseSession struct {
	ctx        context.Context
	cancelFunc context.CancelFunc
}

func (session *baseSession) init(ctx context.Context) {
	session.ctx, session.cancelFunc = context.WithCancel(ctx)
}

func (session *baseSession) auth(id string, secret string, opts ...Option) (
	ctx context.Context, err error,
) {
	var (
		ok   bool
		user User
	)

	if user, ok, err = repo.FindAuthUser(session.ctx, id); err != nil {
		return
	} else if !ok {
		err = ErrInvalidUserCredentials // Don't reveal if a user exists or not
		return
	}

	if user.Secret() != secret {
		log.Printf("failed here 2929\nuser.Secret() = %s\nsecret = %s\n", user.Secret(), secret)
		err = ErrInvalidUserCredentials
		return
	}

	for _, o := range opts {
		if o == IgnoreUnverified {
			return
		}
	}

	if !user.IsVerified() {
		err = ErrUserNotVerified
		return
	}

	ctx = context.WithValue(session.ctx, UserKey, user)
	return
}

// FromContext creates a User from a context.Context.
func FromContext(ctx context.Context) (user User, err error) {
	var ok bool
	if user, ok = ctx.Value(UserKey).(User); !ok {
		err = fmt.Errorf("context must contain current user")
	}

	return
}
