package cli

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lann/localcert"
	"golang.org/x/crypto/acme"
	"gopkg.in/square/go-jose.v2"
)

const (
	defaultServerURL        = "https://api.localcert.dev"
	defaultACMEDirectoryURL = acme.LetsEncryptURL

	filePerm = 0700
)

var (
	flagDataDir          = flag.String("dataDir", "", "default data directory")
	flagServerURL        = flag.String("serverUrl", defaultServerURL, "localcert server URL")
	flagACMEDirectoryURL = flag.String("acmeUrl", defaultACMEDirectoryURL, "ACME directory URL")
	flagACMEAccountFile  = flag.String("acmeAccount", "", "path to ACME account file")
	flagCertificateFile  = flag.String("localCert", "", "path to localcert certificate")
	flagKeyFile          = flag.String("localKey", "", "path to localcert certificate key")
)

type Config struct {
	DataDir         string
	ServerURL       string
	ACMEAccountFile string
	CertificateFile string
	KeyFile         string

	ACME    *ACMEAccount
	acmeKey crypto.Signer
}

func GetConfig() (*Config, error) {
	flag.Parse()

	dataDir := *flagDataDir
	if dataDir == "" {
		userConfigDir, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("user config dir: %w", err)
		}
		dataDir = filepath.Join(userConfigDir, "localcert")

		// In the common case of the default dataDir not yet existing, try creating it
		if _, err := os.Stat(dataDir); errors.Is(err, os.ErrNotExist) {
			err := os.Mkdir(dataDir, filePerm)
			if err != nil {
				return nil, fmt.Errorf("create default config dir: %w", err)
			}
		}
	}

	acmeAccountFile := *flagACMEAccountFile
	if acmeAccountFile == "" {
		acmeAccountFile = filepath.Join(dataDir, "acme_account.json")
	}

	certificateFile := *flagCertificateFile
	if certificateFile == "" {
		certificateFile = filepath.Join(dataDir, "cert.pem")
	}

	keyFile := *flagKeyFile
	if keyFile == "" {
		keyFile = filepath.Join(dataDir, "privkey.pem")
	}

	config := &Config{
		DataDir:         dataDir,
		ServerURL:       *flagServerURL,
		ACMEAccountFile: acmeAccountFile,
		CertificateFile: certificateFile,
		KeyFile:         keyFile,
	}
	if err := config.readOrGenerateACMEAccount(); err != nil {
		return nil, err
	}
	return config, nil
}

func (c *Config) ReadOrGenerateCertificateKey() (crypto.Signer, error) {
	keyBytes, err := os.ReadFile(c.KeyFile)
	if err == nil {
		key, err := x509.ParseECPrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("decode: %w", err)
		}
		return key, nil
	} else if errors.Is(err, os.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate: %w", err)
		}

		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("encode: %w", err)
		}

		if err := os.WriteFile(c.KeyFile, keyBytes, filePerm); err != nil {
			return nil, fmt.Errorf("write %q: %w", c.KeyFile, err)
		}

		return key, nil
	} else {
		return nil, fmt.Errorf("read: %w", err)
	}
}

func (c *Config) ReadCertificate() (*x509.Certificate, error) {
	certBytes, err := os.ReadFile(c.CertificateFile)
	if err != nil {
		return nil, err
	}

	certs, err := x509.ParseCertificates(certBytes)
	if err != nil {
		return nil, err
	}

	return certs[0], nil
}

func (c *Config) Client() *localcert.Client {
	return localcert.Config{
		ACMEPrivateKey:     c.ACME.PrivateKey.Key.(crypto.Signer),
		ACMEDirectoryURL:   c.ACME.DirectoryURL,
		LocalCertServerURL: c.ServerURL,
	}.Client()
}

func (c *Config) WriteACMEAccountFile() error {
	fileBytes, err := json.MarshalIndent(c.ACME, "", "  ")
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	return os.WriteFile(c.ACMEAccountFile, fileBytes, filePerm)
}

type ACMEAccount struct {
	DirectoryURL  string           `json:"directoryURL"`
	PrivateKey    *jose.JSONWebKey `json:"privateKey"`
	AcceptedTerms string           `json:"acceptedTerms"`
}

func (c *Config) readOrGenerateACMEAccount() error {
	fileBytes, err := os.ReadFile(c.ACMEAccountFile)
	if err == nil {
		c.ACME = &ACMEAccount{}
		err := json.Unmarshal(fileBytes, c.ACME)
		if err != nil {
			return fmt.Errorf("decode acmeAccount: %w", err)
		}

		jwk := c.ACME.PrivateKey
		acmeKey, ok := jwk.Key.(crypto.Signer)
		if !ok {
			return fmt.Errorf("decode acmeAccount: invalid privateKey type %T", jwk.Key)
		}
		c.acmeKey = acmeKey
		return nil
	} else if errors.Is(err, os.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		c.ACME = &ACMEAccount{
			DirectoryURL: *flagACMEDirectoryURL,
			PrivateKey:   &jose.JSONWebKey{Key: key},
		}
		c.acmeKey = key
		return nil
	} else {
		return fmt.Errorf("read %q: %w", c.ACMEAccountFile, err)
	}
}
