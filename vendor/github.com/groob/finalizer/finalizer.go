// Package finalizer implements an HTTP Middleware with a callback that's executed at the end
// of the HTTP request.
package finalizer

import (
	"context"
	"net/http"

	kithttp "github.com/go-kit/kit/transport/http"
)

// Middleware calls the ServerFinalizerFunc at the end of an HTTP Request.
func Middleware(finalizer ServerFinalizerFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		iw := &interceptingWriter{w, http.StatusOK, 0}
		defer func() {
			ctx = context.WithValue(ctx, kithttp.ContextKeyResponseHeaders, iw.Header())
			ctx = context.WithValue(ctx, kithttp.ContextKeyResponseSize, iw.written)
			finalizer(ctx, iw.code, r)
		}()
		w = iw

		next.ServeHTTP(w, r)
	})
}

// ServerFinalizerFunc is a function executed at the end of an HTTP request.
type ServerFinalizerFunc func(ctx context.Context, code int, r *http.Request)

// Header returns the HTTP Response headers from a ServerFinalizerFunc context.
func Header(ctx context.Context) (http.Header, bool) {
	header, ok := ctx.Value(kithttp.ContextKeyResponseHeaders).(http.Header)
	return header, ok
}

// ResponseSize returns the written response size from a ServerFinalizerFunc context.
func ResponseSize(ctx context.Context) (int, bool) {
	size, ok := ctx.Value(kithttp.ContextKeyResponseSize).(int)
	return size, ok
}

type interceptingWriter struct {
	http.ResponseWriter
	code    int
	written int64
}

// WriteHeader may not be explicitly called, so care must be taken to
// initialize w.code to its default value of http.StatusOK.
func (w *interceptingWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *interceptingWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.written += int64(n)
	return n, err
}
