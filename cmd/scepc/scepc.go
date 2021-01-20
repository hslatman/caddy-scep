package main

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	scepclient "github.com/micromdm/scep/client"
	"github.com/micromdm/scep/scep"
	"github.com/pkg/errors"
	"go.step.sm/crypto/x509util"
)

// version info
var (
	version = "unreleased"
	gitHash = "unknown"
)

type runCfg struct {
	dir          string
	csrPath      string
	keyPath      string
	keyBits      int
	selfSignPath string
	certPath     string
	cn           string
	org          string
	ou           string
	locality     string
	province     string
	country      string
	challenge    string
	serverURL    string
	caMD5        string
	debug        bool
	logfmt       string
}

func run(cfg runCfg) error {
	ctx := context.Background()
	var logger log.Logger
	{
		if strings.ToLower(cfg.logfmt) == "json" {
			logger = log.NewJSONLogger(os.Stderr)
		} else {
			logger = log.NewLogfmtLogger(os.Stderr)
		}
		stdlog.SetOutput(log.NewStdlibAdapter(logger))
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		if !cfg.debug {
			logger = level.NewFilter(logger, level.AllowInfo())
		}
	}
	lginfo := level.Info(logger)

	client, err := scepclient.New(cfg.serverURL, logger)
	if err != nil {
		return err
	}

	sigAlgo := x509.SHA1WithRSA
	if client.Supports("SHA-256") || client.Supports("SCEPStandard") {
		sigAlgo = x509.SHA256WithRSA
	}

	key, err := loadOrMakeKey(cfg.keyPath, cfg.keyBits)
	if err != nil {
		return err
	}

	opts := &csrOptions{
		cn:        cfg.cn,
		org:       cfg.org,
		country:   strings.ToUpper(cfg.country),
		ou:        cfg.ou,
		locality:  cfg.locality,
		province:  cfg.province,
		challenge: cfg.challenge,
		key:       key,
		sigAlgo:   sigAlgo,
	}

	csr, err := loadOrMakeCSR(cfg.csrPath, opts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var self *x509.Certificate
	cert, err := loadPEMCertFromFile(cfg.certPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		s, err := loadOrSign(cfg.selfSignPath, key, csr)
		if err != nil {
			return err
		}
		self = s
	}

	resp, certNum, err := client.GetCACert(ctx)
	if err != nil {
		return err
	}
	var certs []*x509.Certificate
	{
		if certNum > 1 {
			certs, err = scep.CACerts(resp)
			if err != nil {
				return err
			}
			if len(certs) < 1 {
				return fmt.Errorf("no certificates returned")
			}
		} else {
			certs, err = x509.ParseCertificates(resp)
			if err != nil {
				return err
			}
		}
	}

	var signerCert *x509.Certificate
	{
		if cert != nil {
			signerCert = cert
		} else {
			signerCert = self
		}
	}

	var msgType scep.MessageType
	{
		// TODO validate CA and set UpdateReq if needed
		if cert != nil {
			msgType = scep.RenewalReq
		} else {
			msgType = scep.PKCSReq
		}
	}

	var recipients []*x509.Certificate
	if cfg.caMD5 == "" {
		recipients = certs
	} else {
		r, err := findRecipients(cfg.caMD5, certs)
		if err != nil {
			return err
		}
		recipients = r
	}

	tmpl := &scep.PKIMessage{
		MessageType: msgType,
		Recipients:  recipients,
		SignerKey:   key,
		SignerCert:  signerCert,
	}

	if cfg.challenge != "" && msgType == scep.PKCSReq {
		tmpl.CSRReqMessage = &scep.CSRReqMessage{
			ChallengePassword: cfg.challenge,
		}
	}

	msg, err := scep.NewCSRRequest(csr, tmpl, scep.WithLogger(logger))
	if err != nil {
		return errors.Wrap(err, "creating csr pkiMessage")
	}

	var respMsg *scep.PKIMessage

	for {
		// loop in case we get a PENDING response which requires
		// a manual approval.

		respBytes, err := client.PKIOperation(ctx, msg.Raw)
		if err != nil {
			return errors.Wrapf(err, "PKIOperation for %s", msgType)
		}

		respMsg, err = scep.ParsePKIMessage(respBytes, scep.WithLogger(logger))
		if err != nil {
			return errors.Wrapf(err, "parsing pkiMessage response %s", msgType)
		}

		switch respMsg.PKIStatus {
		case scep.FAILURE:
			return errors.Errorf("%s request failed, failInfo: %s", msgType, respMsg.FailInfo)
		case scep.PENDING:
			lginfo.Log("pkiStatus", "PENDING", "msg", "sleeping for 30 seconds, then trying again.")
			time.Sleep(30 * time.Second)
			continue
		}
		lginfo.Log("pkiStatus", "SUCCESS", "msg", "server returned a certificate.")
		break // on scep.SUCCESS
	}

	if err := respMsg.DecryptPKIEnvelope(signerCert, key); err != nil {
		return errors.Wrapf(err, "decrypt pkiEnvelope, msgType: %s, status %s", msgType, respMsg.PKIStatus)
	}

	respCert := respMsg.CertRepMessage.Certificate
	if err := ioutil.WriteFile(cfg.certPath, pemCert(respCert.Raw), 0666); err != nil {
		return err
	}

	// remove self signer if used
	if self != nil {
		if err := os.Remove(cfg.selfSignPath); err != nil {
			return err
		}
	}

	return nil
}

// Determine the correct recipient based on the fingerprint.
// In case of NDES that is the last certificate in the chain, not the RA cert.
// Return a full chain starting with the cert that matches the fingerprint.
func findRecipients(fingerprint string, certs []*x509.Certificate) ([]*x509.Certificate, error) {
	fingerprint = strings.Join(strings.Split(fingerprint, " "), "")
	fingerprint = strings.ToLower(fingerprint)
	for i, cert := range certs {
		sum := fmt.Sprintf("%x", md5.Sum(cert.Raw))
		if sum == fingerprint {
			return certs[i-1:], nil
		}
	}
	return nil, errors.Errorf("could not find cert for md5 %s", fingerprint)
}

func validateFlags(keyPath, serverURL string) error {
	if keyPath == "" {
		return errors.New("must specify private key path")
	}
	if serverURL == "" {
		return errors.New("must specify server-url flag parameter")
	}
	_, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server-url flag parameter %s", err)
	}
	return nil
}

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
)

// create a new RSA private key
func newRSAKey(bits int) (*rsa.PrivateKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return private, nil
}

// load key if it exists or create a new one
func loadOrMakeKey(path string, rsaBits int) (*rsa.PrivateKey, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		if os.IsExist(err) {
			return loadKeyFromFile(path)
		}
		return nil, err
	}
	defer file.Close()

	// write key
	priv, err := newRSAKey(rsaBits)
	if err != nil {
		return nil, err
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	pemBlock := &pem.Block{
		Type:    rsaPrivateKeyPEMBlockType,
		Headers: nil,
		Bytes:   privBytes,
	}
	if err = pem.Encode(file, pemBlock); err != nil {
		return nil, err
	}
	return priv, nil
}

// load a PEM private key from disk
func loadKeyFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != rsaPrivateKeyPEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
}

const (
	csrPEMBlockType = "CERTIFICATE REQUEST"
)

type csrOptions struct {
	cn, org, country, ou, locality, province, challenge string
	key                                                 *rsa.PrivateKey
}

func loadOrMakeCSR(path string, opts *csrOptions) (*x509.CertificateRequest, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		if os.IsExist(err) {
			return loadCSRfromFile(path)
		}
		return nil, err
	}
	defer file.Close()

	subject := pkix.Name{
		CommonName:         opts.cn,
		Organization:       subjOrNil(opts.org),
		OrganizationalUnit: subjOrNil(opts.ou),
		Province:           subjOrNil(opts.province),
		Locality:           subjOrNil(opts.locality),
		Country:            subjOrNil(opts.country),
	}
	template := x509util.CertificateRequest{
		CertificateRequest: x509.CertificateRequest{
			Subject:            subject,
			SignatureAlgorithm: x509.SHA1WithRSA,
		},
	}
	if opts.challenge != "" {
		template.ChallengePassword = opts.challenge
	}

	derBytes, err := x509util.CreateCertificateRequest(rand.Reader, &template, opts.key)
	pemBlock := &pem.Block{
		Type:  csrPEMBlockType,
		Bytes: derBytes,
	}
	if err := pem.Encode(file, pemBlock); err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(derBytes)
}

// returns nil or []string{input} to populate pkix.Name.Subject
func subjOrNil(input string) []string {
	if input == "" {
		return nil
	}
	return []string{input}
}

// convert DER to PEM format
func pemCSR(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:    csrPEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	return pem.EncodeToMemory(pemBlock)
}

// load PEM encoded CSR from file
func loadCSRfromFile(path string) (*x509.CertificateRequest, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}
	if pemBlock.Type != csrPEMBlockType || len(pemBlock.Headers) != 0 {
		return nil, errors.New("unmatched type or headers")
	}
	return x509.ParseCertificateRequest(pemBlock.Bytes)
}

const (
	certificatePEMBlockType = "CERTIFICATE"
)

func pemCert(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:    certificatePEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	out := pem.EncodeToMemory(pemBlock)
	return out
}

func loadOrSign(path string, priv *rsa.PrivateKey, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		if os.IsExist(err) {
			return loadPEMCertFromFile(path)
		}
		return nil, err
	}
	defer file.Close()
	self, err := selfSign(priv, csr)
	if err != nil {
		return nil, err
	}
	pemBlock := &pem.Block{
		Type:    certificatePEMBlockType,
		Headers: nil,
		Bytes:   self.Raw,
	}
	if err = pem.Encode(file, pemBlock); err != nil {
		return nil, err
	}
	return self, nil
}

func selfSign(priv *rsa.PrivateKey, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 1)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "SCEP SIGNER",
			Organization: csr.Subject.Organization,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}

func loadPEMCertFromFile(path string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != certificatePEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	return x509.ParseCertificate(pemBlock.Bytes)
}

func main() {
	var (
		flVersion           = flag.Bool("version", false, "prints version information")
		flServerURL         = flag.String("server-url", "", "SCEP server url")
		flChallengePassword = flag.String("challenge", "", "enforce a challenge password")
		flPKeyPath          = flag.String("private-key", "", "private key path, if there is no key, scepclient will create one")
		flCertPath          = flag.String("certificate", "", "certificate path, if there is no key, scepclient will create one")
		flKeySize           = flag.Int("keySize", 2048, "rsa key size")
		flOrg               = flag.String("organization", "scep-client", "organization for cert")
		flCName             = flag.String("cn", "scepclient", "common name for certificate")
		flOU                = flag.String("ou", "MDM", "organizational unit for certificate")
		flLoc               = flag.String("locality", "", "locality for certificate")
		flProvince          = flag.String("province", "", "province for certificate")
		flCountry           = flag.String("country", "US", "country code in certificate")

		// in case of multiple certificate authorities, we need to figure out who the recipient of the encrypted
		// data is.
		flCAFingerprint = flag.String("ca-fingerprint", "", "md5 fingerprint of CA certificate for NDES server.")

		flDebugLogging = flag.Bool("debug", false, "enable debug logging")
		flLogJSON      = flag.Bool("log-json", false, "use JSON for log output")
	)
	flag.Parse()

	// print version information
	if *flVersion {
		fmt.Printf("scepclient - %v\n", version)
		fmt.Printf("git revision - %v\n", gitHash)
		os.Exit(0)
	}

	if err := validateFlags(*flPKeyPath, *flServerURL); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	dir := filepath.Dir(*flPKeyPath)
	csrPath := dir + "/csr.pem"
	selfSignPath := dir + "/self.pem"
	if *flCertPath == "" {
		*flCertPath = dir + "/client.pem"
	}
	var logfmt string
	if *flLogJSON {
		logfmt = "json"
	}

	cfg := runCfg{
		dir:          dir,
		csrPath:      csrPath,
		keyPath:      *flPKeyPath,
		keyBits:      *flKeySize,
		selfSignPath: selfSignPath,
		certPath:     *flCertPath,
		cn:           *flCName,
		org:          *flOrg,
		country:      *flCountry,
		locality:     *flLoc,
		ou:           *flOU,
		province:     *flProvince,
		challenge:    *flChallengePassword,
		serverURL:    *flServerURL,
		caMD5:        *flCAFingerprint,
		debug:        *flDebugLogging,
		logfmt:       logfmt,
	}

	if err := run(cfg); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
