package logutil

import (
	"context"
	"net"
	"net/http"

	"github.com/go-kit/kit/log"
	"github.com/groob/finalizer"
)

// NewHTTPLogger returns a Logger from a Go-Kit Logger.
func NewHTTPLogger(logger log.Logger) *HTTPLogger {
	return &HTTPLogger{logger: logger}
}

// HTTPLogger wraps the Go-Kit Logger to return a logger which implements a
// ServerFinalizerFunc.
// The ServerFinalizerFunc can be passed to finalizer.Middleware or a Go-Kit
// Server to create a structured HTTP Logger.
type HTTPLogger struct {
	logger log.Logger
}

// Middleware returns creates an HTTP logging middleware using LoggingFinalizer.
func (l *HTTPLogger) Middleware(next http.Handler) http.Handler {
	return finalizer.Middleware(l.LoggingFinalizer, next)
}

// LoggingFinalizer is a finalizer.ServerFinalizerFunc which logs information about a completed
// HTTP Request.
func (l *HTTPLogger) LoggingFinalizer(ctx context.Context, code int, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	url := *r.URL
	uri := r.RequestURI

	// Requests using the CONNECT method over HTTP/2.0 must use
	// the authority field (aka r.Host) to identify the target.
	// Refer: https://httpwg.github.io/specs/rfc7540.html#CONNECT
	if r.ProtoMajor == 2 && r.Method == "CONNECT" {
		uri = r.Host
	}

	if uri == "" {
		uri = url.RequestURI()
	}

	keyvals := []interface{}{
		"method", r.Method,
		"status", code,
		"proto", r.Proto,
		"host", host,
		"user_agent", r.UserAgent(),
		"path", uri,
	}

	if referer := r.Referer(); referer != "" {
		keyvals = append(keyvals, "referer", referer)
	}

	// check both the finalizer context key and the go-kit one.
	if size, ok := finalizer.ResponseSize(ctx); ok {
		keyvals = append(keyvals, "response_size", size)
	}

	l.logger.Log(keyvals...)
}
