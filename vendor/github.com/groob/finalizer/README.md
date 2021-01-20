[![GoDoc](https://godoc.org/github.com/groob/finalizer?status.svg)](http://godoc.org/github.com/groob/finalizer)

Finalizer is a Go package that implements an HTTP Middleware with a callback that gets called at the end of every request.
Typically used to implement HTTP logging.

The code in this package has been adapted from the Go-Kit [http server code](https://github.com/go-kit/kit/blob/6a894fed38a999e1a0ce384f3a45589f1752d30d/transport/http/server.go#L87-L95).

