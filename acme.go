package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

const LetsEncryptCA = "https://acme-v01.api.letsencrypt.org"

//const LetsEncryptCA = "https://acme-staging.api.letsencrypt.org"

var JWSEncoding = base64.RawURLEncoding

func AcmePost(key *rsa.PrivateKey, url string, data interface{}) (*http.Response, []byte) {
	payload, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("json.Marshal: %s", err)
	}

	jws := Sign(key, payload)
	reqbody, err := json.Marshal(jws)
	if err != nil {
		log.Fatalf("json.Marshal: %s", err)
	}

	resp, err := http.Post(url, "application/jose+json", bytes.NewBuffer(reqbody))
	if err != nil {
		log.Fatalf("http error: %s", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("error reading response body: %s", err)
	}
	return resp, body
}

func AcmeGet(url string) (*http.Response, []byte) {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("http error: %s", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("error reading response body: %s", err)
	}
	return resp, body
}

func getNonce() string {
	resp, err := http.Head(LetsEncryptCA + "/directory")
	if err != nil {
		log.Fatalf("error requesting directory: %s", err)
	}
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		log.Fatalf("server did not respond with nonce")
	}
	return nonce
}

type JSONWebSignature struct {
	Payload   string
	Protected string
	Signature string
}

func Sign(key *rsa.PrivateKey, payload []byte) *JSONWebSignature {
	e := make([]byte, 4)
	binary.BigEndian.PutUint32(e[:], uint32(key.E))
	headers := map[string]interface{}{
		"alg": "RS256",
		"jwk": map[string]string{
			"kty": "RSA",
			"n":   JWSEncoding.EncodeToString(key.N.Bytes()),
			"e":   JWSEncoding.EncodeToString(bytes.TrimLeft(e, "\x00")),
		},
		"nonce": getNonce(),
	}
	headersjson, err := json.Marshal(headers)
	if err != nil {
		log.Fatalf("json.Marshal: %s", err)
	}

	jws := &JSONWebSignature{
		Payload:   JWSEncoding.EncodeToString(payload),
		Protected: JWSEncoding.EncodeToString(headersjson),
	}

	msg := fmt.Sprintf("%s.%s", jws.Protected, jws.Payload)
	hashed := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		log.Fatalf("rsa.SignPKCS1v15: %s", err)
	}
	jws.Signature = JWSEncoding.EncodeToString(sig)

	return jws
}

func Thumbprint(key *rsa.PrivateKey) string {
	e := make([]byte, 4)
	binary.BigEndian.PutUint32(e[:], uint32(key.E))
	se := JWSEncoding.EncodeToString(bytes.TrimLeft(e, "\x00"))
	sn := JWSEncoding.EncodeToString(key.N.Bytes())

	data := fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, se, sn)
	sum := sha256.Sum256([]byte(data))

	return JWSEncoding.EncodeToString(sum[:])
}

func NewKeyFile(path string, bits int) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatal(err)
	}

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	if err := ioutil.WriteFile(path, pemdata, 0400); err != nil {
		log.Fatalf("error writing key file: %s", err)
	}
	log.Printf("created private key: %s", path)
	return key
}

func ReadKeyFile(path string) (*rsa.PrivateKey, error) {
	pemdata, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemdata)
	if block == nil {
		return nil, fmt.Errorf("%s: error decoding PEM data", path)
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("%s: invalid key type: %s", path, block.Type)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing %s: %s", path, err)
	}
	return key, nil
}

func formatBody(resp *http.Response, body []byte) string {
	switch resp.Header.Get("Content-Type") {
	case "application/json", "application/problem+json":
		v := new(interface{})
		if err := json.Unmarshal(body, v); err != nil {
			break
		}
		if b, err := json.MarshalIndent(v, "", "  "); err == nil {
			return string(b)
		}
	}
	return fmt.Sprintf("%s", body)
}
