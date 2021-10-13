# Localcert - get valid TLS certificates for your local network

Localcert combines a custom DNS server with [Let's Encrypt](https://letsencrypt.org)
to make local development with a valid TLS certificate quick and easy.

## Installation

Localcert is a normal Go CLI tool. It can be installed with a working Go developer env with:

```sh
go install github.com/lann/localcert/cmd/localcert@latest
```

You can also download a [release](https://github.com/lann/localcert/releases) binary.

## Usage

```sh
localcert
```

This will provision a domain and wildcard certificate like `*.fsbli4oliukyh3ydjuzx7q2tdq.user.localcert.dev`
for your use. The Localcert DNS server will respond to certain subdomains of your domain:

* `localhost.<your subdomain>.user.localcert.dev` -> `127.0.0.1`
* `ip10-11-12-13.<your subdomain>.user.localcert.dev` -> `10.11.12.13`
  * This form supports IPs in the following [reserved address blocks](https://en.wikipedia.org/wiki/Reserved_IP_addresses#IPv4):
    * `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (private networks)
    * `169.254.0.0/16` (link-local addresses)
    * `127.0.0.0/8` (loopback addresses)
