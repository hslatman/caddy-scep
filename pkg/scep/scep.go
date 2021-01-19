// Copyright 2021 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scep

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a SCEP server handler
type Handler struct {
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.scep",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the ACME server handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	return nil
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// if strings.HasPrefix(r.URL.Path, ash.PathPrefix) {
	// 	ash.acmeEndpoints.ServeHTTP(w, r)
	// 	return nil
	// }
	return next.ServeHTTP(w, r)
}

// Cleanup implements caddy.CleanerUpper and closes any idle databases.
func (h Handler) Cleanup() error {
	// key := ash.getDatabaseKey()
	// deleted, err := databasePool.Delete(key)
	// if deleted {
	// 	ash.logger.Debug("unloading unused CA database", zap.String("db_key", key))
	// }
	// if err != nil {
	// 	ash.logger.Error("closing CA database", zap.String("db_key", key), zap.Error(err))
	// }
	// return err
	return nil
}

// Interface guards
var (
	_ caddy.Module                = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
)
