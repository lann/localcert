package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/lann/localcert"
)

var flagForceRenew = flag.Bool("forceRenew", false, "force renewel of certificate with > 30 days until expiration")

func Provision() {
	config, err := GetConfig()
	if err != nil {
		log.Fatal("Config error: ", err)
	}

	client := config.Client()
	ctx := context.Background()

	cert, err := config.ReadCertificate()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("Error reading existing certificate %q: %v", config.CertificateFile, err)
	}

	var domain string
	if cert != nil {
		domain = cert.Subject.CommonName
		fmt.Printf("Found existing certificate for domain %q\n", domain)
		if !*flagForceRenew {
			expiresIn := time.Until(cert.NotAfter)
			if expiresIn > 30*24*time.Hour {
				fmt.Println("Existing certificate expires in > 30 days and doesn't need to be renewed")
				printCertInfo(config, cert)
				os.Exit(0)
			} else if expiresIn > 0 {
				fmt.Println("Existing certificate expires in < 30 days and will be renewed")
			} else {
				fmt.Println("Existing certificate is expired and will be renewed")
			}
		}
	}

	termsRetry := false
	for {
		account, err := client.EnsureRegistration(ctx, config.ACME.AcceptedTerms, config.ACME.PrivateKey.KeyID)
		if termsErr := (localcert.TermsNotAcceptedError{}); !termsRetry && errors.As(err, &termsErr) {
			PromptRequireAcceptTerms(termsErr.URI)
			config.ACME.AcceptedTerms = termsErr.URI
			termsRetry = true
			continue
		} else if err != nil {
			log.Fatal("Registration error: ", err)
		}
		config.ACME.PrivateKey.KeyID = account.URI
		break
	}
	if err := config.WriteACMEAccountFile(); err != nil {
		log.Fatalf("Error writing acmeAccount file %q: %v", config.ACMEAccountFile, err)
	}

	if domain == "" {
		domain, err = client.GetDomain()
		if err != nil {
			log.Fatal("Error getting localcert domain name: ", err)
		}
	}

	fmt.Printf("Provisioning domain %q...\n", domain)
	order, err := client.ProvisionDomain(ctx, domain)
	if err != nil {
		log.Fatal("Error provisioning domain: ", err)
	}

	certKey, err := config.ReadOrGenerateCertificateKey()
	if err != nil {
		log.Fatal("Certificate key error: ", err)
	}

	fmt.Printf("Domain provisioned; waiting for certificate generation...\n")
	certChain, err := client.GetCertificate(ctx, order, certKey)
	if err != nil {
		log.Fatal("Error fetching certificate: ", err)
	}
	cert, err = x509.ParseCertificate(certChain[0])
	if err != nil {
		log.Fatal("Error parsing generated certificate: ", err)
	}

	var buf bytes.Buffer
	for _, certBytes := range certChain {
		err := pem.Encode(&buf, &pem.Block{Type: certificatePEMType, Bytes: certBytes})
		if err != nil {
			log.Fatal("Error writing certificate: ", err)
		}
	}
	err = os.WriteFile(config.CertificateFile, buf.Bytes(), filePerm)
	if err != nil {
		log.Fatal("Error writing certificate: ", err)
	}

	printCertInfo(config, cert)
}

func printCertInfo(config *Config, cert *x509.Certificate) {
	fmt.Print("\nCertificate expires ", cert.NotAfter, "\n\n")
	fmt.Println("Certificate (chain): ", config.CertificateFile)
	fmt.Println("Certificate privkey: ", config.KeyFile)
}
