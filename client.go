package localcert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/crypto/acme"
	"gopkg.in/square/go-jose.v2"

	"github.com/lann/localcert/internal/acmeutil"
)

const defaultUserAgent = "localcert/1.0"

type Config struct {
	ACMEPrivateKey   crypto.Signer
	ACMEDirectoryURL string

	LocalCertServerURL string
	HTTPClient         *http.Client
	UserAgentPrefix    string
}

func (config Config) Client() *Client {
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	userAgent := config.UserAgentPrefix
	if userAgent == "" {
		userAgent = defaultUserAgent
	}

	return &Client{
		serverURL: config.LocalCertServerURL,
		acmeClient: &acme.Client{
			Key:          config.ACMEPrivateKey,
			DirectoryURL: config.ACMEDirectoryURL,
			HTTPClient:   httpClient,
			UserAgent:    userAgent,
		},
	}
}

type Client struct {
	serverURL  string
	acmeClient *acme.Client
}

func (c *Client) EnsureRegistration(ctx context.Context, acceptedTermsURI string, accountURL string) (*acme.Account, error) {
	dir, err := c.acmeClient.Discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	if dir.Terms != "" && acceptedTermsURI != dir.Terms {
		return nil, TermsNotAcceptedError{URI: dir.Terms}
	}

	if accountURL == "" {
		account, err := c.acmeClient.Register(ctx, &acme.Account{}, acme.AcceptTOS)
		if err != nil {
			return nil, fmt.Errorf("register: %w", err)
		}
		return account, nil
	} else {
		account, err := c.acmeClient.GetReg(ctx, accountURL)
		if err != nil {
			return nil, fmt.Errorf("account: %w", err)
		}
		if account.Status != acme.StatusValid {
			return nil, fmt.Errorf("account %q statis is %q", account.URI, account.Status)
		}
		return account, nil
	}
}

func (c *Client) GetDomain() (string, error) {
	acctReq, err := acmeutil.CaptureAccountRequest(c.acmeClient)
	if err != nil {
		return "", err
	}

	var domainRes DomainResult
	err = c.localcertPost("/domain", DomainRequest{AccountRequest: acctReq}, &domainRes)
	if err != nil {
		return "", fmt.Errorf("domain: %w", err)
	}
	return domainRes.Domain, nil
}

func (c *Client) ProvisionDomain(ctx context.Context, domain string) (*acme.Order, error) {
	id := acme.AuthzID{Type: "dns", Value: domain}
	order, err := c.acmeClient.AuthorizeOrder(ctx, []acme.AuthzID{id})
	if err != nil {
		return nil, fmt.Errorf("new order: %w", err)
	}
	// TODO: validate Order (?)

	authzURI := order.AuthzURLs[0]
	authzReq, err := acmeutil.CaptureAuthorizationRequest(c.acmeClient, authzURI)
	if err != nil {
		return nil, err
	}

	var provisionRes ProvisionResult
	err = c.localcertPost("/provision", ProvisionRequest{
		PublicKey:            &jose.JSONWebKey{Key: c.acmeClient.Key.Public()},
		AuthorizationRequest: authzReq,
	}, &provisionRes)
	if err != nil {
		return nil, fmt.Errorf("provision: %w", err)
	}

	_, err = c.acmeClient.Accept(ctx, &acme.Challenge{URI: provisionRes.ProvisionedChallengeURL})
	if err != nil {
		return nil, fmt.Errorf("challenge accept: %w", err)
	}

	order, err = c.acmeClient.WaitOrder(ctx, order.URI)
	if err != nil {
		if chal, err := c.acmeClient.GetChallenge(ctx, provisionRes.ProvisionedChallengeURL); err == nil {
			log.Printf("Challenge error: %#v", chal.Error)
		}
		return nil, fmt.Errorf("order wait: %w", err)
	}

	return order, nil
}

func (c *Client) GetCertificate(ctx context.Context, order *acme.Order, certKey crypto.Signer) ([][]byte, error) {
	name := order.Identifiers[0].Value
	req := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: name},
		DNSNames: []string{name},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, req, certKey)
	if err != nil {
		return nil, fmt.Errorf("create csr: %w", err)
	}

	bundle, _, err := c.acmeClient.CreateOrderCert(ctx, order.FinalizeURL, csrBytes, true)
	return bundle, err
}

func (c *Client) localcertPost(urlSuffix string, req interface{}, res interface{}) error {
	url := c.serverURL + urlSuffix
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("json encode: %w", err)
	}
	resp, err := c.acmeClient.HTTPClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if statusErr := acmeutil.ErrorFromResponse(resp); statusErr != nil {
		return statusErr
	}

	err = json.NewDecoder(resp.Body).Decode(res)
	if err != nil {
		return fmt.Errorf("json decode: %w", err)
	}
	return nil
}

type TermsNotAcceptedError struct {
	URI string
}

func (tne TermsNotAcceptedError) Error() string {
	return "terms not accepted"
}
