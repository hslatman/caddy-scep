// Package scep provides common functionality for encoding and decoding
// Simple Certificate Enrolment Protocol pki messages as defined by
// https://tools.ietf.org/html/draft-gutmann-scep-02
package scep

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"

	"github.com/micromdm/scep/scep/internal/pkcs7"
)

// errors
var (
	errNotImplemented     = errors.New("not implemented")
	errUnknownMessageType = errors.New("unknown messageType")
)

// The MessageType attribute specifies the type of operation performed
// by the transaction.  This attribute MUST be included in all PKI
// messages.
//
// The following message types are defined:
type MessageType string

// Undefined message types are treated as an error.
const (
	CertRep    MessageType = "3"
	RenewalReq             = "17"
	UpdateReq              = "18"
	PKCSReq                = "19"
	CertPoll               = "20"
	GetCert                = "21"
	GetCRL                 = "22"
)

// PKIStatus is a SCEP pkiStatus attribute which holds transaction status information.
// All SCEP responses MUST include a pkiStatus.
//
// The following pkiStatuses are defined:
type PKIStatus string

// Undefined pkiStatus attributes are treated as an error
const (
	SUCCESS PKIStatus = "0"
	FAILURE           = "2"
	PENDING           = "3"
)

// FailInfo is a SCEP failInfo attribute
//
// The FailInfo attribute MUST contain one of the following failure
// reasons:
type FailInfo string

//
const (
	BadAlg          FailInfo = "0"
	BadMessageCheck          = "1"
	BadRequest               = "2"
	BadTime                  = "3"
	BadCertID                = "4"
)

// SenderNonce is a random 16 byte number.
// A sender must include the senderNonce in each transaction to a recipient.
type SenderNonce []byte

// The RecipientNonce MUST be copied from the SenderNonce
// and included in the reply.
type RecipientNonce []byte

// The TransactionID is a text
// string generated by the client when starting a transaction. The
// client MUST generate a unique string as the transaction identifier,
// which MUST be used for all PKI messages exchanged for a given
// enrolment, encoded as a PrintableString.
type TransactionID string

// SCEP OIDs
var (
	oidSCEPmessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPpkiStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidSCEPfailInfo       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSCEPsenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPrecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidSCEPtransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
	oidChallengePassword  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
)

// PKIMessage defines the possible SCEP message types
type PKIMessage struct {
	TransactionID
	MessageType
	SenderNonce
	*CertRepMessage
	*CSRReqMessage

	// DER Encoded PKIMessage
	Raw []byte

	// parsed
	p7 *pkcs7.PKCS7

	// decrypted enveloped content
	pkiEnvelope []byte

	// Used to sign message
	Recipients []*x509.Certificate

	// Signer info
	SignerKey  *rsa.PrivateKey
	SignerCert *x509.Certificate
}

// CertRepMessage is a type of PKIMessage
type CertRepMessage struct {
	PKIStatus
	RecipientNonce
	FailInfo

	Certificate *x509.Certificate

	degenerate []byte
}

// CSRReqMessage can be of the type PKCSReq/RenewalReq/UpdateReq
// and includes a PKCS#10 CSR request.
// The content of this message is protected
// by the recipient public key(example CA)
type CSRReqMessage struct {
	// PKCS#10 Certificate request inside the envelope
	CSR *x509.CertificateRequest

	ChallengePassword string
}

// ParsePKIMessage unmarshals a PKCS#7 signed data into a PKI message struct
func ParsePKIMessage(data []byte) (*PKIMessage, error) {
	// parse PKCS#7 signed data
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}

	var tID TransactionID
	if err := p7.UnmarshalSignedAttribute(oidSCEPtransactionID, &tID); err != nil {
		return nil, err
	}

	var msgType MessageType
	if err := p7.UnmarshalSignedAttribute(oidSCEPmessageType, &msgType); err != nil {
		return nil, err
	}

	msg := &PKIMessage{
		TransactionID: tID,
		MessageType:   msgType,
		Raw:           data,
		p7:            p7,
	}

	if err := msg.parseMessageType(); err != nil {
		return nil, err
	}

	return msg, nil
}

func (msg *PKIMessage) parseMessageType() error {
	switch msg.MessageType {
	case CertRep:
		var status PKIStatus
		if err := msg.p7.UnmarshalSignedAttribute(oidSCEPpkiStatus, &status); err != nil {
			return err
		}
		var rn RecipientNonce
		if err := msg.p7.UnmarshalSignedAttribute(oidSCEPrecipientNonce, &rn); err != nil {
			return err
		}
		if len(rn) == 0 {
			return errors.New("scep pkiMessage must include recipientNonce attribute")
		}
		cr := &CertRepMessage{
			PKIStatus:      status,
			RecipientNonce: rn,
		}
		switch status {
		case SUCCESS:
			break
		case FAILURE:
			var fi FailInfo
			if err := msg.p7.UnmarshalSignedAttribute(oidSCEPfailInfo, &fi); err != nil {
				return err
			}
			if fi == "" {
				return errors.New("scep pkiStatus FAILURE must have a failInfo attribute")
			}
			cr.FailInfo = fi
		case PENDING:
			return errNotImplemented
		default:
			return errors.New("unknown scep pkiStatus")
		}
		msg.CertRepMessage = cr
		return nil
	case PKCSReq, UpdateReq, RenewalReq:
		var sn SenderNonce
		if err := msg.p7.UnmarshalSignedAttribute(oidSCEPsenderNonce, &sn); err != nil {
			return err
		}
		if len(sn) == 0 {
			return errors.New("scep pkiMessage must include senderNonce attribute")
		}
		msg.SenderNonce = sn
		return nil
	case GetCRL, GetCert, CertPoll:
		return errNotImplemented
	default:
		return errUnknownMessageType
	}
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type tbsCertificateRequest struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     publicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type certificateRequest struct {
	Raw                asn1.RawContent
	TBSCSR             tbsCertificateRequest
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// stdlib ignores the challengePassword attribute in csr
func parseChallengePassword(asn1Data []byte) (string, error) {
	type attribute struct {
		ID    asn1.ObjectIdentifier
		Value asn1.RawValue `asn1:"set"`
	}
	var csr certificateRequest
	rest, err := asn1.Unmarshal(asn1Data, &csr)
	if err != nil {
		return "", err
	} else if len(rest) != 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return "", err
	}

	var password string
	for _, rawAttr := range csr.TBSCSR.RawAttributes {
		var attr attribute
		_, err := asn1.Unmarshal(rawAttr.FullBytes, &attr)
		if err != nil {
			return "", err
		}
		if attr.ID.Equal(oidChallengePassword) {
			_, err := asn1.Unmarshal(attr.Value.Bytes, &password)
			if err != nil {
				return "", err
			}
		}
	}

	return password, nil
}

// AddChallenge adds a challenge password to the CSR
func addChallenge(csr *x509.CertificateRequest, challenge string) ([]byte, error) {
	// unmarshal csr
	var req certificateRequest
	rest, err := asn1.Unmarshal(csr.Raw, &req)
	if err != nil {
		return nil, err
	} else if len(rest) != 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return nil, err
	}

	passwordAttribute := pkix.AttributeTypeAndValue{
		Type:  oidChallengePassword,
		Value: []byte(challenge),
	}
	b, err := asn1.Marshal(passwordAttribute)

	var rawAttribute asn1.RawValue
	rest, err = asn1.Unmarshal(b, &rawAttribute)
	if err != nil {
		return nil, err
	} else if len(rest) != 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return nil, err
	}

	// append attribute
	req.TBSCSR.RawAttributes = append(req.TBSCSR.RawAttributes, rawAttribute)

	// recreate request
	tbsCSR := tbsCertificateRequest{
		Version:       0,
		Subject:       req.TBSCSR.Subject,
		PublicKey:     req.TBSCSR.PublicKey,
		RawAttributes: req.TBSCSR.RawAttributes,
	}

	tbsCSRContents, err := asn1.Marshal(tbsCSR)
	if err != nil {
		return nil, err
	}
	tbsCSR.Raw = tbsCSRContents

	// marshal csr with challenge password
	csrBytes, err := asn1.Marshal(certificateRequest{
		TBSCSR:             tbsCSR,
		SignatureAlgorithm: req.SignatureAlgorithm,
		SignatureValue:     req.SignatureValue,
	})
	if err != nil {
		return nil, err
	}

	return csrBytes, nil
}

// DecryptPKIEnvelope decrypts the pkcs envelopedData inside the SCEP PKIMessage
func (msg *PKIMessage) DecryptPKIEnvelope(cert *x509.Certificate, key *rsa.PrivateKey) error {
	p7, err := pkcs7.Parse(msg.p7.Content)
	if err != nil {
		return err
	}
	msg.pkiEnvelope, err = p7.Decrypt(cert, key)
	if err != nil {
		return err
	}

	switch msg.MessageType {
	case CertRep:
		certs, err := CACerts(msg.pkiEnvelope)
		if err != nil {
			return err
		}
		msg.CertRepMessage.Certificate = certs[0]
		return nil
	case PKCSReq, UpdateReq, RenewalReq:
		csr, err := x509.ParseCertificateRequest(msg.pkiEnvelope)
		if err != nil {
			return err
		}
		// check for challengePassword
		cp, err := parseChallengePassword(msg.pkiEnvelope)
		if err != nil {
			return err
		}
		msg.CSRReqMessage = &CSRReqMessage{
			CSR:               csr,
			ChallengePassword: cp,
		}
		return nil
	case GetCRL, GetCert, CertPoll:
		return errNotImplemented
	default:
		return errUnknownMessageType
	}
}

// SignCSR creates an x509.Certificate based on a template and Cert Authority credentials
// returns a new PKIMessage with CertRep data
func (msg *PKIMessage) SignCSR(crtAuth *x509.Certificate, keyAuth *rsa.PrivateKey, template *x509.Certificate) (*PKIMessage, error) {
	// check if CSRReqMessage has already been decrypted
	if msg.CSRReqMessage.CSR == nil {
		if err := msg.DecryptPKIEnvelope(crtAuth, keyAuth); err != nil {
			return nil, err
		}
	}
	// sign the CSR creating a DER encoded cert
	crtBytes, err := x509.CreateCertificate(rand.Reader, template, crtAuth, msg.CSRReqMessage.CSR.PublicKey, keyAuth)
	if err != nil {
		return nil, err
	}
	// parse the certificate
	crt, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		return nil, err
	}

	// create a degenerate cert structure
	deg, err := DegenerateCertificates([]*x509.Certificate{crt})
	if err != nil {
		return nil, err
	}

	// encrypt degenerate data using the original messages recipients
	e7, err := pkcs7.Encrypt(deg, msg.p7.Certificates)
	if err != nil {
		return nil, err
	}

	// PKIMessageAttributes to be signed
	config := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			pkcs7.Attribute{
				Type:  oidSCEPtransactionID,
				Value: msg.TransactionID,
			},
			pkcs7.Attribute{
				Type:  oidSCEPpkiStatus,
				Value: SUCCESS,
			},
			pkcs7.Attribute{
				Type:  oidSCEPmessageType,
				Value: CertRep,
			},
			pkcs7.Attribute{
				Type:  oidSCEPrecipientNonce,
				Value: msg.SenderNonce,
			},
		},
	}

	signedData, err := pkcs7.NewSignedData(e7)
	if err != nil {
		return nil, err
	}
	// add the certificate into the signed data type
	// this cert must be added before the signedData because the recipient will expect it
	// as the first certificate in the array
	signedData.AddCertificate(crt)
	// sign the attributes
	if err := signedData.AddSigner(crtAuth, keyAuth, config); err != nil {
		return nil, err
	}

	certRepBytes, err := signedData.Finish()
	if err != nil {
		return nil, err
	}

	cr := &CertRepMessage{
		PKIStatus:      SUCCESS,
		RecipientNonce: RecipientNonce(msg.SenderNonce),
		Certificate:    crt,
		degenerate:     deg,
	}

	// create a CertRep message from the original
	crepMsg := &PKIMessage{
		Raw:            certRepBytes,
		TransactionID:  msg.TransactionID,
		MessageType:    CertRep,
		CertRepMessage: cr,
	}

	return crepMsg, nil
}

// DegenerateCertificates creates degenerate certificates pkcs#7 type
func DegenerateCertificates(certs []*x509.Certificate) ([]byte, error) {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	degenerate, err := pkcs7.DegenerateCertificate(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return degenerate, nil
}

// CACerts extract CA Certificate or chain from pkcs7 degenerate signed data
func CACerts(data []byte) ([]*x509.Certificate, error) {
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	return p7.Certificates, nil
}

// NewCSRRequest creates a scep PKI PKCSReq/UpdateReq message
func NewCSRRequest(csr *x509.CertificateRequest, tmpl *PKIMessage) (*PKIMessage, error) {
	csrBytes := csr.Raw
	if tmpl.CSRReqMessage != nil {
		if tmpl.ChallengePassword != "" {
			b, err := addChallenge(csr, tmpl.ChallengePassword)
			if err != nil {
				return nil, err
			}
			csrBytes = b
		}
	}
	e7, err := pkcs7.Encrypt(csrBytes, tmpl.Recipients)
	if err != nil {
		return nil, err
	}

	signedData, err := pkcs7.NewSignedData(e7)
	if err != nil {
		return nil, err
	}

	// create transaction ID from public key hash
	tID, err := newTransactionID(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	sn, err := newNonce()
	if err != nil {
		return nil, err
	}

	// PKIMessageAttributes to be signed
	config := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			pkcs7.Attribute{
				Type:  oidSCEPtransactionID,
				Value: tID,
			},
			pkcs7.Attribute{
				Type:  oidSCEPmessageType,
				Value: tmpl.MessageType,
			},
			pkcs7.Attribute{
				Type:  oidSCEPsenderNonce,
				Value: sn,
			},
		},
	}

	// sign attributes
	if err := signedData.AddSigner(tmpl.SignerCert, tmpl.SignerKey, config); err != nil {
		return nil, err
	}

	rawPKIMessage, err := signedData.Finish()
	if err != nil {
		return nil, err
	}

	cr := &CSRReqMessage{
		CSR: csr,
	}

	newMsg := &PKIMessage{
		Raw:           rawPKIMessage,
		MessageType:   tmpl.MessageType,
		TransactionID: tID,
		SenderNonce:   sn,
		CSRReqMessage: cr,
	}

	return newMsg, nil
}

func newNonce() (SenderNonce, error) {
	size := 16
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return SenderNonce{}, err
	}
	return SenderNonce(b), nil
}

// use public key to create a deterministric transactionID
func newTransactionID(key crypto.PublicKey) (TransactionID, error) {
	id, err := generateSubjectKeyID(key)
	if err != nil {
		return "", err
	}

	encHash := base64.StdEncoding.EncodeToString(id)
	return TransactionID(encHash), nil
}

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKey struct {
	N *big.Int
	E int
}

// GenerateSubjectKeyID generates SubjectKeyId used in Certificate
// ID is 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
func generateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	var pubBytes []byte
	var err error
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(rsaPublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("only RSA public key is supported")
	}

	hash := sha1.Sum(pubBytes)

	return hash[:], nil
}
