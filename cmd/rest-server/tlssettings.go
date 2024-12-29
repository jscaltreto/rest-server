package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

type tlsSettings struct {
	enabled           bool
	key, cert, caCert string
}

// config returns a tls.Config based on the settings
func (t *tlsSettings) config() (*tls.Config, error) {
	if !t.enabled {
		return nil, nil
	}

	var err error
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(t.cert, t.key)
	if err != nil {
		return nil, fmt.Errorf("unable to load TLS key pair: %w", err)
	}

	cfg := &tls.Config{Certificates: certs}

	if t.caCert != "" {
		caCert, err := os.ReadFile(t.caCert)
		if err != nil {
			return nil, fmt.Errorf("unable to read CA certificate: %w", err)
		}
		cfg.ClientCAs = x509.NewCertPool()
		if !cfg.ClientCAs.AppendCertsFromPEM(caCert) {
			return nil, errors.New("unable to add CA certificate to pool")
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return cfg, nil
}
