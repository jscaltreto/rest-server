package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	restserver "github.com/restic/rest-server"
)

const (
	serverKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMaVLVHdmFAnlsZsFKEmRhxA+aCChCNBgjMj/sQonErioAoGCCqGSM49
AwEHoUQDQgAEUxhCvoV5d2Kp9YGddtK3oFyVQcGn4gD0nHXnc/TTXe5oZiGOwST3
RKoyZSrv4jXYEDTbmdYW/HCfMW+fPLRe7g==
-----END EC PRIVATE KEY-----`

	serverCert = `-----BEGIN CERTIFICATE-----
MIIBmTCCAUCgAwIBAgIUTbxFvUdaxOoSBMV5JAQBL525I5swCgYIKoZIzj0EAwIw
FDESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTI0MTIyNTE0MDYwMFoXDTM0MTIyMzE0
MDYwMFowFDESMBAGA1UEAxMJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEUxhCvoV5d2Kp9YGddtK3oFyVQcGn4gD0nHXnc/TTXe5oZiGOwST3RKoy
ZSrv4jXYEDTbmdYW/HCfMW+fPLRe7qNwMG4wDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFFU05IVxIJtt
kp1q45t/tDZXJ9pjMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAKBggqhkjO
PQQDAgNHADBEAiApFHKSK+bpX+qToCXWpGt8CL+VZzyLCPwqKYaee91j0QIgI4+p
SfPhAnt0Wx/nUHGJIEPJ5T0K+oCEv+mrAaRJBHk=
-----END CERTIFICATE-----`

	clientKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMCcKEzZF/0/XlQAyUqsGfkjyINTbQgVoynqnmGKmaHIoAoGCCqGSM49
AwEHoUQDQgAETaWyItlONTsh8kRm63MdLmvzlT3p3TzWVsrBRJ8tE6hWZOguriBW
SmBa5gfpXUEvRZC4GrrPNhIjp7ZNYMIeuQ==
-----END EC PRIVATE KEY-----`

	clientCert = `-----BEGIN CERTIFICATE-----
MIIBmzCCAUCgAwIBAgIUGPrCJSCAJ3Z6ZIctKKzibciNyaswCgYIKoZIzj0EAwIw
FDESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTI0MTIyNTE0MDYwMFoXDTM0MTIyMzE0
MDYwMFowFDESMBAGA1UEAxMJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAETaWyItlONTsh8kRm63MdLmvzlT3p3TzWVsrBRJ8tE6hWZOguriBWSmBa
5gfpXUEvRZC4GrrPNhIjp7ZNYMIeuaNwMG4wDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
JQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFHuWBRDirjd9
yklChRs6AZxY75DsMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAKBggqhkjO
PQQDAgNJADBGAiEAo0iRDW7aBuggcQDWkzSSuxqr+nZHztLILbQlPIxsKXoCIQCh
4xHnACSNsVnuPgAOzzU2N8XxTSY7XxsOmYHGZ87mnQ==
-----END CERTIFICATE-----`

	caCert = `-----BEGIN CERTIFICATE-----
MIIBmjCCAUGgAwIBAgIIX3Scim21wAQwCgYIKoZIzj0EAwIwFDESMBAGA1UEAxMJ
bG9jYWxob3N0MB4XDTI0MTIyNTE0MDUyOFoXDTM0MTIyMzE0MTAyOFowFDESMBAG
A1UEAxMJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwvQYzXGd
gdLdkqmPuMuogVvhuCmexuq3ef64I5h0xciwqtsKNVsgrSZM+f3AxIv4Jbac7lRq
S69Qrgcdw2BcR6N9MHswDgYDVR0PAQH/BAQDAgGmMB0GA1UdJQQWMBQGCCsGAQUF
BwMBBggrBgEFBQcDAjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTEK4Ft5Q3y
bK2n5FIKvN9/DfReXjAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZI
zj0EAwIDRwAwRAIgCeMYMDTjhKVsHP3T3FVP+bHxVkifvXOUQR0WNT2g/34CIHR3
Xzl/BnMLD0m6erLaKKL/As/krmV+NA2Oj6SWSoP6
-----END CERTIFICATE-----`
)

func TestTLSSettings(t *testing.T) {
	type expected struct {
		TLSKey    string
		TLSCert   string
		TLSCaCert string
		Error     bool
	}
	type passed struct {
		Path      string
		TLS       bool
		MTLS      bool
		TLSKey    string
		TLSCert   string
		TLSCaCert string
	}

	var tests = []struct {
		passed   passed
		expected expected
	}{
		{passed{TLS: false}, expected{"", "", "", false}},
		{passed{TLS: true}, expected{
			filepath.Join(os.TempDir(), "restic/private_key"),
			filepath.Join(os.TempDir(), "restic/public_key"),
			"",
			false,
		}},
		{passed{
			Path: os.TempDir(),
			TLS:  true,
		}, expected{
			filepath.Join(os.TempDir(), "private_key"),
			filepath.Join(os.TempDir(), "public_key"),
			"",
			false,
		}},
		{passed{
			TLS:  true,
			MTLS: true,
		}, expected{
			filepath.Join(os.TempDir(), "restic/private_key"),
			filepath.Join(os.TempDir(), "restic/public_key"),
			filepath.Join(os.TempDir(), "restic/ca_cert"),
			false,
		}},
		{passed{
			Path: os.TempDir(),
			TLS:  true,
			MTLS: true,
		}, expected{
			filepath.Join(os.TempDir(), "private_key"),
			filepath.Join(os.TempDir(), "public_key"),
			filepath.Join(os.TempDir(), "ca_cert"),
			false,
		}},
		{passed{Path: os.TempDir(), TLS: true, TLSKey: "/etc/restic/key", TLSCert: "/etc/restic/cert"}, expected{"/etc/restic/key", "/etc/restic/cert", "", false}},
		{
			passed{Path: os.TempDir(), TLS: true, MTLS: true, TLSKey: "/etc/restic/key", TLSCert: "/etc/restic/cert", TLSCaCert: "/etc/restic/ca_cert"},
			expected{"/etc/restic/key", "/etc/restic/cert", "/etc/restic/ca_cert", false},
		},
		{passed{Path: os.TempDir(), TLS: true, MTLS: false, TLSCaCert: "/etc/restic/ca_cert"}, expected{"", "", "", true}},
		{passed{Path: os.TempDir(), TLS: false, MTLS: true}, expected{"", "", "", true}},
		{passed{Path: os.TempDir(), TLS: false, TLSKey: "/etc/restic/key", TLSCert: "/etc/restic/cert"}, expected{"", "", "", true}},
		{passed{Path: os.TempDir(), TLS: false, TLSKey: "/etc/restic/key"}, expected{"", "", "", true}},
		{passed{Path: os.TempDir(), TLS: false, TLSCert: "/etc/restic/cert"}, expected{"", "", "", true}},
		{passed{Path: os.TempDir(), TLS: false, TLSCaCert: "/etc/restic/ca_cert"}, expected{"", "", "", true}},
	}

	for _, test := range tests {
		app := newRestServerApp()
		t.Run("", func(t *testing.T) {
			// defer func() { restserver.Server = defaultConfig }()
			if test.passed.Path != "" {
				app.Server.Path = test.passed.Path
			}
			app.Server.TLS = test.passed.TLS
			app.Server.MTLS = test.passed.MTLS
			app.Server.TLSKey = test.passed.TLSKey
			app.Server.TLSCert = test.passed.TLSCert
			app.Server.TLSCaCert = test.passed.TLSCaCert

			got, err := app.tlsSettings()
			if err != nil && !test.expected.Error {
				t.Fatalf("tls_settings returned err (%v)", err)
			}
			if test.expected.Error {
				if err == nil {
					t.Fatalf("Error not returned properly (%v)", test)
				} else {
					return
				}
			}
			if got.enabled != test.passed.TLS {
				t.Errorf("TLS enabled, want (%v), got (%v)", test.passed.TLS, got.enabled)
			}
			wantKey := test.expected.TLSKey
			if got.key != wantKey {
				t.Errorf("wrong TLSPrivPath path, want (%v), got (%v)", wantKey, got.key)
			}

			wantCert := test.expected.TLSCert
			if got.cert != wantCert {
				t.Errorf("wrong TLSCertPath path, want (%v), got (%v)", wantCert, got.cert)
			}

			wantCaCert := test.expected.TLSCaCert
			if got.caCert != wantCaCert {
				t.Errorf("wrong TLSCertPath path, want (%v), got (%v)", wantCaCert, got.caCert)
			}

		})
	}
}

func TestGetHandler(t *testing.T) {
	dir, err := ioutil.TempDir("", "rest-server-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := os.Remove(dir)
		if err != nil {
			t.Fatal(err)
		}
	}()

	getHandler := restserver.NewHandler

	// With NoAuth = false and no .htpasswd
	_, err = getHandler(&restserver.Server{Path: dir})
	if err == nil {
		t.Errorf("NoAuth=false: expected error, got nil")
	}

	// With NoAuth = true and no .htpasswd
	_, err = getHandler(&restserver.Server{NoAuth: true, Path: dir})
	if err != nil {
		t.Errorf("NoAuth=true: expected no error, got %v", err)
	}

	// With NoAuth = false and custom .htpasswd
	htpFile, err := ioutil.TempFile(dir, "custom")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := os.Remove(htpFile.Name())
		if err != nil {
			t.Fatal(err)
		}
	}()
	_, err = getHandler(&restserver.Server{HtpasswdPath: htpFile.Name()})
	if err != nil {
		t.Errorf("NoAuth=false with custom htpasswd: expected no error, got %v", err)
	}

	// Create .htpasswd
	htpasswd := filepath.Join(dir, ".htpasswd")
	err = ioutil.WriteFile(htpasswd, []byte(""), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := os.Remove(htpasswd)
		if err != nil {
			t.Fatal(err)
		}
	}()

	// With NoAuth = false and with .htpasswd
	_, err = getHandler(&restserver.Server{Path: dir})
	if err != nil {
		t.Errorf("NoAuth=false with .htpasswd: expected no error, got %v", err)
	}
}

// helper method to test the app. Starts app with passed arguments,
// then will call the callback function which can make requests against
// the application. If the callback function fails due to errors returned
// by http.Do() (i.e. *url.Error), then it will be retried until successful,
// or the passed timeout passes.
func testServerWithArgs(args []string, timeout time.Duration, cb func(context.Context, *restServerApp) error) error {
	// create the app with passed args
	app := newRestServerApp()
	app.CmdRoot.SetArgs(args)

	// create context that will timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// wait group for our client and server tasks
	jobs := &sync.WaitGroup{}
	jobs.Add(2)

	// run the server, saving the error
	var serverErr error
	go func() {
		defer jobs.Done()
		defer cancel() // if the server is stopped, no point keep the client alive
		serverErr = app.CmdRoot.ExecuteContext(ctx)
	}()

	// run the client, saving the error
	var clientErr error
	go func() {
		defer jobs.Done()
		defer cancel() // once the client is done, stop the server

		var urlError *url.Error

		// execute in loop, as we will retry for network errors
		// (such as the server hasn't started yet)
		for {
			clientErr = cb(ctx, app)
			switch {
			case clientErr == nil:
				return // success, we're done
			case errors.As(clientErr, &urlError):
				// if a network error (url.Error), then wait and retry
				// as server may not be ready yet
				select {
				case <-time.After(time.Millisecond * 100):
					continue
				case <-ctx.Done(): // unless we run out of time first
					clientErr = context.Canceled
					return
				}
			default:
				return // other error type, we're done
			}
		}
	}()

	// wait for both to complete
	jobs.Wait()

	// report back if either failed
	if clientErr != nil || serverErr != nil {
		return fmt.Errorf("client or server error, client: %v, server: %v", clientErr, serverErr)
	}

	return nil
}

func testListen(t *testing.T, tls bool, client *http.Client, extraArgs ...string) {
	td := t.TempDir()

	// create some content and parent dirs
	if err := os.MkdirAll(filepath.Join(td, "data", "repo1"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(td, "data", "repo1", "config"), []byte("foo"), 0700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(td, "data", "public_key"), []byte(serverCert), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(td, "data", "private_key"), []byte(serverKey), 0600); err != nil {
		t.Fatal(err)
	}
	scheme := "http"

	baseArgs := append([]string{"--no-auth", "--path", filepath.Join(td, "data")}, extraArgs...)
	if tls {
		scheme = "https"
		baseArgs = append(baseArgs, "--tls")
	}

	for _, args := range [][]string{
		{"--listen", "127.0.0.1:0"},    // test emphemeral port
		{"--listen", "127.0.0.1:9000"}, // test "normal" port
		{"--listen", "127.0.0.1:9000"}, // test that server was shutdown cleanly and that we can re-use that port
	} {
		err := testServerWithArgs(append(baseArgs, args...), time.Second*30, func(ctx context.Context, app *restServerApp) error {
			for _, test := range []struct {
				Path       string
				StatusCode int
			}{
				{"/repo1/", http.StatusMethodNotAllowed},
				{"/repo1/config", http.StatusOK},
				{"/repo2/config", http.StatusNotFound},
			} {
				listenAddr := app.ListenerAddress()
				if listenAddr == nil {
					return &url.Error{} // return this type of err, as we know this will retry
				}
				port := strings.Split(listenAddr.String(), ":")[1]

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s://localhost:%s%s", scheme, port, test.Path), nil)
				if err != nil {
					return err
				}
				resp, err := client.Do(req)
				if err != nil {
					return err
				}
				resp.Body.Close()
				if resp.StatusCode != test.StatusCode {
					return fmt.Errorf("expected %d from server, instead got %d (path %s)", test.StatusCode, resp.StatusCode, test.Path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestHttpListen(t *testing.T) {
	testListen(t, false, http.DefaultClient)
}

func TestHttpsListen(t *testing.T) {
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM([]byte(caCert)) {
		t.Fatal("failed to append CA cert")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}
	testListen(t, true, &http.Client{Transport: tr})
}

func TestMtlsListen(t *testing.T) {
	td := t.TempDir()
	caCertPath := filepath.Join(td, "ca_cert")
	if err := os.WriteFile(caCertPath, []byte(caCert), 0600); err != nil {
		t.Fatal(err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM([]byte(caCert)) {
		t.Fatal("failed to append CA cert")
	}

	clientCertificate, err := tls.X509KeyPair([]byte(clientCert), []byte(clientKey))
	if err != nil {
		t.Fatal(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      certPool,
			Certificates: []tls.Certificate{clientCertificate},
		},
	}

	testListen(t, true, &http.Client{Transport: tr}, "--mtls", "--tls-ca-cert", caCertPath)
}
