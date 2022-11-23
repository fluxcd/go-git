// Package client contains helper function to deal with the different client
// protocols.
package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	gohttp "net/http"
	"time"

	"github.com/fluxcd/go-git/v5/plumbing/transport"
	"github.com/fluxcd/go-git/v5/plumbing/transport/file"
	"github.com/fluxcd/go-git/v5/plumbing/transport/git"
	"github.com/fluxcd/go-git/v5/plumbing/transport/http"
	"github.com/fluxcd/go-git/v5/plumbing/transport/ssh"
)

// Protocols are the protocols supported by default.
var Protocols = map[string]transport.Transport{
	"http":  http.DefaultClient,
	"https": http.DefaultClient,
	"ssh":   ssh.DefaultClient,
	"git":   git.DefaultClient,
	"file":  file.DefaultClient,
}

var dialer = net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

func defaultTransport() *gohttp.Transport {
	t := gohttp.DefaultTransport.(*gohttp.Transport).Clone()
	if t.TLSClientConfig != nil {
		t.TLSClientConfig = &tls.Config{}
	}
	return t
}

var insecureClient = http.NewClient(&gohttp.Client{
	Transport: func() *gohttp.Transport {
		t := defaultTransport()
		t.TLSClientConfig.InsecureSkipVerify = true
		return t
	}(),
})

// InstallProtocol adds or modifies an existing protocol.
func InstallProtocol(scheme string, c transport.Transport) {
	if c == nil {
		delete(Protocols, scheme)
		return
	}

	Protocols[scheme] = c
}

// NewClient returns the appropriate client among of the set of known protocols:
// http://, https://, ssh:// and file://.
// See `InstallProtocol` to add or modify protocols.
func NewClient(endpoint *transport.Endpoint) (transport.Transport, error) {
	return getTransport(endpoint)
}

func getTransport(endpoint *transport.Endpoint) (transport.Transport, error) {
	if endpoint.Protocol == "https" {
		if endpoint.InsecureSkipTLS {
			return insecureClient, nil
		}

		if len(endpoint.CaBundle) != 0 {
			rootCAs, _ := x509.SystemCertPool()
			if rootCAs == nil {
				rootCAs = x509.NewCertPool()
			}
			rootCAs.AppendCertsFromPEM(endpoint.CaBundle)
			return http.NewClient(&gohttp.Client{
				Transport: func() *gohttp.Transport {
					t := defaultTransport()
					t.TLSClientConfig.RootCAs = rootCAs
					return t
				}(),
			}), nil
		}
	}

	f, ok := Protocols[endpoint.Protocol]
	if !ok {
		return nil, fmt.Errorf("unsupported scheme %q", endpoint.Protocol)
	}

	if f == nil {
		return nil, fmt.Errorf("malformed client for scheme %q, client is defined as nil", endpoint.Protocol)
	}
	return f, nil
}
