# acme-nano

acme-nano is a tool for generating HTTPS certificates that are signed by the
[Let's Encrypt](https://letsencrypt.org/) Certificate Authority.  acme-nano
is less than 600 lines of code and has no external dependencies, making it
easy to audit.

## Getting started

### One-time setup

1. Install acme-nano (requires Go version 1.5+):

        $ go get github.com/davidlazar/acme-nano

2. Register an account:

        $ acme-nano register -account acme.key -email admin@example.com

3. Authorize account to manage your domain:

        $ sudo acme-nano authorize -account acme.key -domain example.com

Type `acme-nano authorize -h` for instructions on how to run the authorize
command without root.

### Generate certificates

    $ acme-nano cert -account acme.key -domain example.com -chain

You'll probably want to run the cert command in a monthly cronjob.
