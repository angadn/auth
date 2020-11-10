package auth

import (
	"context"
	"net/http"
)

// HTTPSession implements Session over HTTP headers.
type HTTPSession struct {
	baseSession

	req *http.Request
	rw  http.ResponseWriter
	err error
}

const (
	headerUserID     = "X-Auth-User-ID"
	headerUserSecret = "X-Auth-Secret"
)

// NewHTTPSession is a constructor for HTTPSession.
func NewHTTPSession(rw http.ResponseWriter, req *http.Request) (session *HTTPSession) {
	if !isRepoSet {
		panic("auth.WithUserRepository(*) must be called")
	}

	session = new(HTTPSession)
	session.init(req.Context())
	session.req, session.rw = req, rw

	return
}

// Auth authenticates a Session based.
func (session *HTTPSession) Auth() (ctx context.Context, err error) {
	id := session.req.Header.Get(headerUserID)
	sec := session.req.Header.Get(headerUserSecret)

	ctx, err = session.auth(id, sec)
	session.err = err
	return
}

// Cancel checks if an error has occurred thus far and writes it to the HTTP response.
func (session *HTTPSession) Cancel() {
	session.cancelFunc()
	switch session.err {
	case nil:
		session.rw.WriteHeader(200)
		session.rw.Write([]byte{})
	default:
		session.rw.WriteHeader(400)
		session.rw.Write([]byte(session.err.Error()))
	}
}

// HTTPHandler to chain with our HandlerFuncs, performing Auth before invoking them.
func HTTPHandler(handler http.HandlerFunc) (authHandler http.HandlerFunc) {
	authHandler = func(rw http.ResponseWriter, req *http.Request) {
		var (
			err     error
			session *HTTPSession
			ctx     context.Context
		)

		session = NewHTTPSession(rw, req)
		if ctx, err = session.Auth(); err != nil {
			session.Cancel()
			return
		}

		handler(rw, req.WithContext(ctx))
	}

	return
}
