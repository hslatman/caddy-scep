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
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"go.uber.org/zap"

	x509cli "github.com/smallstep/cli/crypto/x509util"

	//"github.com/smallstep/cli/crypto/x509util"

	_ "github.com/micromdm/scep/depot"
	scepserver "github.com/micromdm/scep/server"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a SCEP server handler
type Handler struct {
	CA         string `json:"ca,omitempty"`
	Host       string `json:"host,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`

	logger  *zap.Logger
	handler http.Handler
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

	h.processDefaults()

	h.logger = ctx.Logger(h)

	pkiModule, err := ctx.App("pki")
	if err != nil {
		return err
	}

	pkiApp := pkiModule.(*caddypki.PKI)
	fmt.Println(pkiApp)
	fmt.Println(fmt.Sprintf("%#+v", pkiApp.CAs))
	ca, ok := pkiApp.CAs[h.CA]
	if !ok {
		return fmt.Errorf("no certificate authority configured with id: %s", h.CA)
	}

	fmt.Println(ca)

	depot, err := NewCaddyDepot(ca)
	if err != nil {
		return err
	}

	svcOptions := []scepserver.ServiceOption{
		scepserver.ChallengePassword("password"), // This seems to be a shared secret, but for all clients?
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

	// var h http.Handler // http handler
	// {
	e := scepserver.MakeServerEndpoints(svc)

	fmt.Println(e)

	logger := log.NewJSONLogger(os.Stderr)
	debug := level.Debug(logger)

	e.GetEndpoint = scepserver.EndpointLoggingMiddleware(debug)(e.GetEndpoint)
	e.PostEndpoint = scepserver.EndpointLoggingMiddleware(debug)(e.PostEndpoint)

	h.handler = scepserver.MakeHTTPHandler(e, svc, log.With(debug, "component", "http"))

	fmt.Println(h.handler)

	// e.GetEndpoint = scep.EndpointLoggingMiddleware(lginfo)(e.GetEndpoint)
	// e.PostEndpoint = scep.EndpointLoggingMiddleware(lginfo)(e.PostEndpoint)
	// h = scep.MakeHTTPHandler(e, svc, log.With(lginfo, "component", "http"))
	// }

	// TODO: link scepserver to the pki (and thus storage)
	// TODO: add routes (and serve them)
	// TODO: how does auth work with the scepserver? ChallengePassword? Something different?
	// TODO: implement according to RFC
	// TODO: add tests
	// TODO: ensure smaller dependency stack (i.e. no go-kit if it's not necessary; might result in providing more scep of our own)

	return nil
}

func (h *Handler) processDefaults() {

	if h.CA == "" {
		h.CA = "local"
	}

	if h.Host == "" {
		h.Host = "localhost"
	}

	if h.PathPrefix == "" {
		// "/cgi-bin/pkiclient.exe" ?
		h.PathPrefix = "/scep"
	}
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	if strings.HasPrefix(r.URL.Path, h.PathPrefix) {
		fmt.Println("serving scep endpoint")

		fmt.Println(fmt.Sprintf("%#+v", r))

		h.handler.ServeHTTP(w, r)

		fmt.Println("done")

		return nil
	}

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
	fmt.Println("ca")

	rootCert := cd.ca.RootCertificate()

	rootKey, err := cd.ca.RootKey()
	if err != nil {
		return nil, nil, err
	}

	rk, ok := rootKey.(crypto.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("no valid root key")
	}

	fmt.Println(rootCert)
	fmt.Println("rk")
	fmt.Println(rk)

	// rpk, ok := rk.(rsa.PrivateKey)
	// if !ok {
	// 	return nil, nil, fmt.Errorf("no valid rsa root key")
	// }

	fmt.Println(fmt.Sprintf("%T", rk)) // *ecdsa.PrivateKey

	// privatekey, err := rsa.GenerateKey(rand.Reader, 4096)
	// if err != nil {
	// 	fmt.Printf("Cannot generate RSA key\n")
	// 	os.Exit(1)
	// }
	//publickey := &privatekey.PublicKey

	rootProfile, err := x509cli.NewRootProfile("localhost")
	if err != nil {
		return nil, nil, err
	}
	//rootProfile.SetSubjectPrivateKey(privatekey)
	rootProfile.Subject().NotAfter = time.Now().Add(time.Hour * 1) // TODO: make configurable

	rootProfile.GenerateKeyPair("RSA", "", 4096)

	// pub, priv, err := x509cli.GenerateKeyPair("RSA", "", 4096)
	// if err != nil {
	// 	return nil, nil, err
	// }

	certBytes, err := rootProfile.CreateCertificate()
	if err != nil {
		return nil, nil, err
	}

	privKey := rootProfile.SubjectPrivateKey()
	cert, err := x509.ParseCertificate(certBytes)

	fmt.Println(privKey)
	fmt.Println(fmt.Sprintf("%T", privKey))

	rpk, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("no valid rsa root key")
	}

	fmt.Println(cert)
	fmt.Println(fmt.Sprintf("%T", cert))
	fmt.Println(fmt.Sprintf("%#+v", cert.PublicKey))

	//return []*x509.Certificate{rootCert}, privatekey, nil
	return []*x509.Certificate{cert}, rpk, nil
}

func (cd *CaddyDepot) Put(name string, crt *x509.Certificate) error {
	fmt.Println("put")
	return nil
}

func (cd *CaddyDepot) Serial() (*big.Int, error) {
	fmt.Println("serial")
	return nil, nil
}

func (cd *CaddyDepot) HasCN(cn string, allowTime int, cert *x509.Certificate, revokeOldCertificate bool) (bool, error) {
	fmt.Println("hascn")
	return false, nil
}

// Interface guards
var (
	_ caddy.Module                = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
)
