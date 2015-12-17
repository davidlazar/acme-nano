package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

var accountKeyFile string

// Command is based on the Command struct from cmd/go
type Command struct {
	Run       func(cmd *Command, args []string)
	UsageLine string
	Long      string
	Flag      flag.FlagSet
}

// Name returns the command's name: the first word in the usage line.
func (c *Command) Name() string {
	name := c.UsageLine
	i := strings.Index(name, " ")
	if i >= 0 {
		name = name[:i]
	}
	return name
}

func (c *Command) Usage() {
	fmt.Fprintf(os.Stderr, "usage: %s\n\n", c.UsageLine)
	fmt.Fprintf(os.Stderr, "%s\n", strings.TrimSpace(c.Long))
	os.Exit(2)
}

var commands = []*Command{
	cmdRegister,
	cmdAuthorize,
	cmdCert,
}

func main() {
	flag.Usage = usage
	flag.Parse()
	log.SetFlags(0)

	args := flag.Args()
	if len(args) < 1 {
		usage()
	}

	for _, cmd := range commands {
		if cmd.Name() == args[0] {
			cmd.Flag.Usage = func() { cmd.Usage() }
			cmd.Flag.Parse(args[1:])
			args = cmd.Flag.Args()
			cmd.Run(cmd, args)
			os.Exit(0)
		}
	}

	fmt.Fprintf(os.Stderr, "acme-nano: unknown subcommand %q\nRun 'acme-nano -h' for usage.\n", args[0])
	os.Exit(1)
}

var usageText = `acme-nano is a tool for generating HTTPS certificates.

Usage:

	acme-nano command [arguments]

The commands are:

	register    register account on the ACME server
	authorize   authorize account to manage domains
	cert        generate signed certificates

Use "acme-nano command -h" for more information about a command.

Getting started (one-time setup):

	Register an account:
	$ acme-nano register -account acme.key -email admin@example.com

	Authorize account to manage your domain:
	$ sudo acme-nano authorize -account acme.key -domain example.com

Generate a certificate (run this in a monthly cronjob):

	$ acme-nano cert -account acme.key -domain example.com -chain
`

func usage() {
	fmt.Fprintln(os.Stderr, usageText)
	os.Exit(2)
}
