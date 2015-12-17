package main

import (
	"crypto/rsa"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

var cmdAuthorize = &Command{
	Run:       Authorize,
	UsageLine: "authorize -account <keyfile> -domain <domain>",
	Long: `
Authorize the given account to generate certificates for <domain>.

To prove ownership of the domain, this subcommand binds a web
server to port 80, which usually requires superuser permissions.

On Linux, you can avoid running acme-nano as root by giving the
acme-nano binary the necessary capability:

	$ sudo setcap cap_net_bind_service+ep /path/to/acme-nano

The authorize command usually only needs to be run once per domain.
`,
}

func init() {
	cmdAuthorize.Flag.StringVar(&accountKeyFile, "account", "", "account key file")
	cmdAuthorize.Flag.StringVar(&authorizeDomain, "domain", "", "domain to be claimed")
}

var authorizeDomain string

type authorization struct {
	Status     string       `json:"status"`
	Challenges []*challenge `json:"challenges"`
}

type challenge struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	URI    string `json:"uri"`
	Token  string `json:"token"`
}

func Authorize(cmd *Command, args []string) {
	if authorizeDomain == "" || accountKeyFile == "" {
		log.Printf("usage error: missing required flags")
		cmd.Usage()
	}

	key, err := ReadKeyFile(accountKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	resp, body := AcmePost(key, LetsEncryptCA+"/acme/new-authz", map[string]interface{}{
		"resource": "new-authz",
		"identifier": map[string]string{
			"type":  "dns",
			"value": authorizeDomain,
		},
	})
	if resp.StatusCode != http.StatusCreated {
		log.Fatalf("unexpected response when creating authorization: %s\n%s", resp.Status, formatBody(resp, body))
	}

	auth := new(authorization)
	if err := json.Unmarshal(body, auth); err != nil {
		log.Fatalf("error parsing authorization: %s\nbody: %s", err, body)
	}
	httpChallenge := findHTTPChallenge(auth.Challenges)
	keyAuth := httpChallenge.Token + "." + Thumbprint(key)

	go serveChallenge(key, httpChallenge.Token, keyAuth)

	resp, body = AcmePost(key, httpChallenge.URI, map[string]interface{}{
		"resource":         "challenge",
		"keyAuthorization": keyAuth,
	})
	if resp.StatusCode != http.StatusAccepted {
		log.Fatalf("unexpected response when triggering challenge: %s\n%s", resp.Status, formatBody(resp, body))
	}

	for {
		resp, body := AcmeGet(httpChallenge.URI)
		if resp.StatusCode >= http.StatusBadRequest {
			log.Fatalf("unexpected challenge response status: %s", resp.Status)
		}

		ch := new(challenge)
		if err := json.Unmarshal(body, ch); err != nil {
			log.Fatalf("error decoding challenge: %s", err)
		}

		switch ch.Status {
		case "pending":
			// ok
		case "valid":
			log.Printf("authorized %s for domain %s\n%s", accountKeyFile, authorizeDomain, formatBody(resp, body))
			return
		case "invalid":
			log.Fatalf("unable to solve challenge for domain %s", authorizeDomain)
		default:
			log.Fatalf("unexpected challenge status: %s", ch.Status)
		}

		time.Sleep(1 * time.Second)
	}
}

func serveChallenge(accountKey *rsa.PrivateKey, token string, keyAuth string) {
	path := "/.well-known/acme-challenge/" + token

	http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(keyAuth))
	})

	if err := http.ListenAndServe(":80", nil); err != nil {
		log.Fatalf("http.ListenAndServer: %s", err)
	}
}

func findHTTPChallenge(challenges []*challenge) *challenge {
	for _, ch := range challenges {
		if ch.Type == "http-01" {
			return ch
		}
	}
	log.Fatal("http-01 challenge not found")
	return nil
}
