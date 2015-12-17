package main

import (
	"log"
	"net/http"
	"os"
)

var cmdRegister = &Command{
	Run:       Register,
	UsageLine: "register -account <keyfile> -email <email>",
	Long: `
Register an account on the ACME server.

An account is represented by a key pair stored in <keyfile>.
If <keyfile> does not exist, a new key pair is generated and
stored there.

The -email flag specifies an email address that can be used
to recover an account, if the private key is lost.
`,
}

func init() {
	cmdRegister.Flag.StringVar(&accountKeyFile, "account", "", "account key file")
	cmdRegister.Flag.StringVar(&registerEmail, "email", "", "contact email address")
}

var registerEmail string

func Register(cmd *Command, args []string) {
	if registerEmail == "" || accountKeyFile == "" {
		log.Printf("usage error: missing required flags")
		cmd.Usage()
	}

	key, err := ReadKeyFile(accountKeyFile)
	if os.IsNotExist(err) {
		key = NewKeyFile(accountKeyFile, 4096)
	} else if err != nil {
		log.Fatal(err)
	}

	resp, body := AcmePost(key, LetsEncryptCA+"/acme/new-reg", map[string]interface{}{
		"resource":  "new-reg",
		"agreement": "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf",
		"contact":   []string{"mailto:" + registerEmail},
	})

	switch resp.StatusCode {
	case http.StatusCreated:
		log.Printf("registered %s:\n%s", accountKeyFile, formatBody(resp, body))
	case http.StatusConflict:
		log.Printf("%s is already registered:\n%s", accountKeyFile, formatBody(resp, body))
	default:
		log.Printf("unexpected server response: %s\n%s", resp.Status, formatBody(resp, body))
	}
}
