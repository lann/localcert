package acmeutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"golang.org/x/crypto/acme"
)

const RequestContentType = "application/jose+json"

var errCaptured = errors.New("request captured")

type requestCaptor struct {
	realTransport http.RoundTripper
	captureURL    string
	lastRequest   *http.Request
}

var _ http.RoundTripper = (*requestCaptor)(nil)

func (c *requestCaptor) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() != c.captureURL {
		// TODO: make this transport configurable (?)
		log.Printf("Skipping capture: %q != %q", req.URL, c.captureURL)
		return c.realTransport.RoundTrip(req)
	}
	c.lastRequest = req
	return nil, errCaptured
}

func (c *requestCaptor) setupDeferTeardown(client *acme.Client, captureURL string) func() {
	c.captureURL = captureURL

	// Stash current http.Transport; relies on implementation of acme.Client (!)
	oldTransport := client.HTTPClient.Transport

	c.realTransport = oldTransport
	if c.realTransport == nil {
		c.realTransport = http.DefaultTransport
	}

	client.HTTPClient.Transport = c
	return func() {
		client.HTTPClient.Transport = oldTransport
		c.captureURL = ""
	}
}

func (c *requestCaptor) verifyCapture(err error) (*http.Request, error) {
	// Verify the capture happened and not some other error
	if !errors.Is(err, errCaptured) {
		return nil, fmt.Errorf("request capture failed: %w", err)
	}
	// Verify request Content-Type
	contentType := c.lastRequest.Header.Get("Content-Type")
	if contentType != RequestContentType {
		return c.lastRequest, fmt.Errorf("request content type %q != %q", contentType, RequestContentType)
	}
	return c.lastRequest, nil
}

func (c *requestCaptor) verifyCaptureBody(err error) ([]byte, error) {
	req, err := c.verifyCapture(err)
	if req != nil {
		defer req.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_, err = ParseSignedRequest(body)
	if err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	return body, nil
}

func CaptureAccountRequest(client *acme.Client) ([]byte, error) {
	ctx := context.Background()
	discover, err := client.Discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("discover: %w", err)
	}
	captor := &requestCaptor{}
	defer captor.setupDeferTeardown(client, discover.RegURL)()
	_, captureErr := client.GetReg(ctx, "")
	return captor.verifyCaptureBody(captureErr)
}

func CaptureAuthorizationRequest(client *acme.Client, authzURL string) ([]byte, error) {
	captor := &requestCaptor{}
	defer captor.setupDeferTeardown(client, authzURL)()
	_, captureErr := client.GetAuthorization(context.Background(), authzURL)
	return captor.verifyCaptureBody(captureErr)
}
