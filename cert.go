package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"
)

var cmdCert = &Command{
	Run:       Cert,
	UsageLine: "cert -account <keyfile> -domain <domain> [-o <file>] [-p <file>] [-chain]",
	Long: `
Cert generates HTTPS certificates signed by the Let's Encrypt CA.

The -o flag specifies where to write the new certificate
(default is <domain>.cert.crt).

The -p flag specifies where to write the private key for
the new certificate (default is <domain>.cert.key).

If -chain is specified, the resulting certificate includes the
intermediate (issuer) certificate.
`,
}

func init() {
	cmdCert.Flag.StringVar(&accountKeyFile, "account", "", "account key file")
	cmdCert.Flag.StringVar(&certDomain, "domain", "", "domain to issue certificate for")
	cmdCert.Flag.StringVar(&certCertFile, "o", "", "certificate output (default: <domain>.cert.crt)")
	cmdCert.Flag.StringVar(&certPrivateKeyFile, "p", "", "private key output (default: <domain>.cert.key)")
	cmdCert.Flag.BoolVar(&certChain, "chain", false, "include intermediate certificate in result")
}

var (
	certDomain         string
	certPrivateKeyFile string
	certCertFile       string
	certChain          bool
)

func Cert(cmd *Command, args []string) {
	if certDomain == "" || accountKeyFile == "" {
		log.Printf("usage error: missing required flags")
		cmd.Usage()
	}
	if certPrivateKeyFile == "" {
		certPrivateKeyFile = certDomain + ".cert.key"
	}
	if certCertFile == "" {
		certCertFile = certDomain + ".cert.crt"
	}

	key, err := ReadKeyFile(accountKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	certKey := NewKeyFile(certPrivateKeyFile, 2048)

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: certDomain,
		},
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certKey)
	if err != nil {
		log.Fatalf("error creating certificate request: %s", err)
	}

	resp, body := AcmePost(key, LetsEncryptCA+"/acme/new-cert", map[string]interface{}{
		"resource": "new-cert",
		"csr":      JWSEncoding.EncodeToString(csr),
	})
	if resp.StatusCode != http.StatusCreated {
		log.Fatalf("unexpected response when creating new cert: %s\n%s", resp.Status, formatBody(resp, body))
	}

	// TODO the ACME spec says that the certificate may not be ready in the
	// POST response
	if len(body) == 0 {
		log.Fatalf("error: empty body\ntry to retrieve the certificate from: %s", resp.Header.Get("Location"))
	}

	cert, err := x509.ParseCertificate(body)
	if err != nil {
		log.Fatalf("failed to parse certificate: %s", err)
	}

	issuer := getIssuer()
	verifyCert(cert, issuer)

	var resultCerts []*x509.Certificate
	if certChain {
		resultCerts = []*x509.Certificate{cert, issuer}
	} else {
		resultCerts = []*x509.Certificate{cert}
	}

	buf := new(bytes.Buffer)
	for _, c := range resultCerts {
		err := pem.Encode(buf,
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: c.Raw,
			},
		)
		if err != nil {
			log.Fatalf("failed to write PEM block: %s", err)
		}
	}
	if err := ioutil.WriteFile(certCertFile, buf.Bytes(), 0644); err != nil {
		log.Fatalf("error writing certificate file: %s", err)
	}
	log.Printf("created certificate for %s: %s", certDomain, certCertFile)
}

func getIssuer() *x509.Certificate {
	resp, body := AcmeGet(LetsEncryptCA + "/acme/issuer-cert")
	if resp.StatusCode != http.StatusOK || len(body) == 0 {
		log.Fatalf("unable to get issuer certificate: %s", resp.Status)
	}

	issuer, err := x509.ParseCertificate(body)
	if err != nil {
		log.Fatalf("failed to parse issuer certificate: %s", err)
	}
	return issuer
}

func verifyCert(cert, issuer *x509.Certificate) {
	pool := x509.NewCertPool()
	pool.AddCert(issuer)

	_, err := cert.Verify(x509.VerifyOptions{
		DNSName:       certDomain,
		Intermediates: pool,
	})
	if err != nil {
		log.Printf("warning: unable to verify certificate: %s", err)
	}
}
