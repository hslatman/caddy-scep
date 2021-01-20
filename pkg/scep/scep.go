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
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"go.uber.org/zap"

	_ "github.com/micromdm/scep/depot"
	scepserver "github.com/micromdm/scep/server"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a SCEP server handler
type Handler struct {
	logger *zap.Logger
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
	h.logger = ctx.Logger(h)

	pkiModule, err := ctx.App("pki")
	if err != nil {
		return err
	}

	caLocal := "local"

	pkiApp := pkiModule.(*caddypki.PKI)
	fmt.Println(pkiApp)
	fmt.Println(fmt.Sprintf("%#+v", pkiApp.CAs))
	ca, ok := pkiApp.CAs[caLocal]
	if !ok {
		return fmt.Errorf("no certificate authority configured with id: %s", caLocal)
	}

	fmt.Println(ca)

	depot, err := NewCaddyDepot(ca)
	if err != nil {
		return err
	}

	svcOptions := []scepserver.ServiceOption{
		// scepserver.ChallengePassword(*flChallengePassword),
		// scepserver.WithCSRVerifier(csrVerifier),
		// scepserver.CAKeyPassword([]byte(*flCAPass)),
		scepserver.AllowRenewal(14),   // 14 days
		scepserver.ClientValidity(60), // 60 days
		// scepserver.WithLogger(logger),
	}

	fmt.Println(svcOptions)

	svc, err := scepserver.NewService(depot, svcOptions...)
	if err != nil {
		h.logger.Error(err.Error())
		return err
	}

	fmt.Println(svc)
	//svc = scepserver.NewLoggingService(log.With(lginfo, "component", "scep_service"), svc)

	// TODO: link scepserver to the pki (and thus storage)
	// TODO: add routes (and serve them)
	// TODO: how does auth work with the scepserver? ChallengePassword? Something different?
	// TODO: implement according to RFC
	// TODO: add tests
	// TODO: ensure smaller dependency stack (i.e. no go-kit if it's not necessary; might result in providing more scep of our own)

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

type CaddyDepot struct {
	ca *caddypki.CA
}

func NewCaddyDepot(ca *caddypki.CA) (*CaddyDepot, error) {
	return &CaddyDepot{
		ca: ca,
	}, nil
}

func (cd *CaddyDepot) CA(pass []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	return nil, nil, nil
}

func (cd *CaddyDepot) Put(name string, crt *x509.Certificate) error {
	return nil
}

func (cd *CaddyDepot) Serial() (*big.Int, error) {
	return nil, nil
}

func (cd *CaddyDepot) HasCN(cn string, allowTime int, cert *x509.Certificate, revokeOldCertificate bool) error {
	return nil
}

// Interface guards
var (
	_ caddy.Module                = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
)
