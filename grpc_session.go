package auth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// GRPCSession is an implementation of Session for gRPC, and checks for User and Secret
// in the Auth protobuf-generated message-struct.
type GRPCSession struct {
	baseSession

	md metadata.MD
}

// NewGRPCSession is a constructor for GRPCSession. It mutates the Context pointed to, by
// inserting the User into it's Values when Auth() is called.
func NewGRPCSession(ctx context.Context) (session GRPCSession) {
	if !isRepoSet {
		panic("auth.WithUserRepository(*) must be called")
	}

	session.init(ctx)
	return
}

// Auth checks whether the User and Secret are valid credentials per our Repository.
func (session GRPCSession) Auth() (ctx context.Context, err error) {
	var (
		ok bool
		md metadata.MD
	)

	if md, ok = metadata.FromIncomingContext(session.ctx); !ok {
		err = ErrMissingUserCredentials
		return
	}

	var userMD []string
	if userMD = md.Get("user"); len(userMD) < 1 {
		err = ErrMissingUserCredentials
		return
	}

	var secretMD []string
	if secretMD = md.Get("secret"); len(secretMD) < 1 {
		err = ErrMissingUserCredentials
		return
	}

	ctx, err = session.baseSession.auth(
		userMD[0], secretMD[0],
	)

	return
}

// Cancel the underlying gRPC Context.
func (session GRPCSession) Cancel() {
	session.cancelFunc()
}

// GRPCUnaryInterceptorOverride is an interface a gRPC Server can implement to override
// the global server GRPCUnaryInterceptor installation and implement custom
// authentication.
type GRPCUnaryInterceptorOverride interface {
	Auth(ctx context.Context, fullMethodName string) (
		authCtx context.Context, err error,
	)
}

// GRPCUnaryInterceptor to Auth incoming requests.
var GRPCUnaryInterceptor grpc.UnaryServerInterceptor = func(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (resp interface{}, err error) {
	if custom, ok := info.Server.(GRPCUnaryInterceptorOverride); ok {
		if ctx, err = custom.Auth(ctx, info.FullMethod); err != nil {
			return
		}
	} else if ctx, err = GRPCAuthFunc(ctx); err != nil {
		return
	}

	resp, err = handler(ctx, req)
	return
}

// GRPCAuthFunc matches grpc_auth.AuthFunc, in case you want to use
// github.com/grpc-ecosystem/go-grpc-middleware
func GRPCAuthFunc(ctx context.Context) (authCtx context.Context, err error) {
	if authCtx, err = NewGRPCSession(ctx).Auth(); err != nil {
		return
	}

	return
}
