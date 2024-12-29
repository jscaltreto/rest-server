package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"syscall"

	restserver "github.com/restic/rest-server"
	"github.com/spf13/cobra"
)

type restServerApp struct {
	CmdRoot    *cobra.Command
	Server     restserver.Server
	CpuProfile string

	listenerAddressMu sync.Mutex
	listenerAddress   net.Addr // set after startup
}

// cmdRoot is the base command when no other command has been specified.
func newRestServerApp() *restServerApp {
	rv := &restServerApp{
		CmdRoot: &cobra.Command{
			Use:           "rest-server",
			Short:         "Run a REST server for use with restic",
			SilenceErrors: true,
			SilenceUsage:  true,
			Args: func(cmd *cobra.Command, args []string) error {
				if len(args) != 0 {
					return fmt.Errorf("rest-server expects no arguments - unknown argument: %s", args[0])
				}
				return nil
			},
			Version: fmt.Sprintf("rest-server %s compiled with %v on %v/%v\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH),
		},
		Server: restserver.Server{
			Path:   filepath.Join(os.TempDir(), "restic"),
			Listen: ":8000",
		},
	}
	rv.CmdRoot.RunE = rv.runRoot
	flags := rv.CmdRoot.Flags()

	flags.StringVar(&rv.CpuProfile, "cpu-profile", rv.CpuProfile, "write CPU profile to file")
	flags.BoolVar(&rv.Server.Debug, "debug", rv.Server.Debug, "output debug messages")
	flags.StringVar(&rv.Server.Listen, "listen", rv.Server.Listen, "listen address")
	flags.StringVar(&rv.Server.Log, "log", rv.Server.Log, "write HTTP requests in the combined log format to the specified `filename` (use \"-\" for logging to stdout)")
	flags.Int64Var(&rv.Server.MaxRepoSize, "max-size", rv.Server.MaxRepoSize, "the maximum size of the repository in bytes")
	flags.StringVar(&rv.Server.Path, "path", rv.Server.Path, "data directory")
	flags.BoolVar(&rv.Server.TLS, "tls", rv.Server.TLS, "turn on TLS support")
	flags.BoolVar(&rv.Server.MTLS, "mtls", rv.Server.MTLS, "turn on mTLS support")
	flags.StringVar(&rv.Server.TLSCert, "tls-cert", rv.Server.TLSCert, "TLS certificate path")
	flags.StringVar(&rv.Server.TLSKey, "tls-key", rv.Server.TLSKey, "TLS key path")
	flags.StringVar(&rv.Server.TLSCaCert, "tls-ca-cert", rv.Server.TLSCaCert, "TLS CA certificate path for mTLS")
	flags.BoolVar(&rv.Server.NoAuth, "no-auth", rv.Server.NoAuth, "disable .htpasswd authentication")
	flags.BoolVar(&rv.Server.NoMtlsAuth, "no-mtls-auth", rv.Server.NoMtlsAuth, "disable mTLS authentication when mTLS is enabled")
	flags.StringVar(&rv.Server.HtpasswdPath, "htpasswd-file", rv.Server.HtpasswdPath, "location of .htpasswd file (default: \"<data directory>/.htpasswd)\"")
	flags.BoolVar(&rv.Server.NoVerifyUpload, "no-verify-upload", rv.Server.NoVerifyUpload,
		"do not verify the integrity of uploaded data. DO NOT enable unless the rest-server runs on a very low-power device")
	flags.BoolVar(&rv.Server.AppendOnly, "append-only", rv.Server.AppendOnly, "enable append only mode")
	flags.BoolVar(&rv.Server.PrivateRepos, "private-repos", rv.Server.PrivateRepos, "users can only access their private repo")
	flags.BoolVar(&rv.Server.Prometheus, "prometheus", rv.Server.Prometheus, "enable Prometheus metrics")
	flags.BoolVar(&rv.Server.PrometheusNoAuth, "prometheus-no-auth", rv.Server.PrometheusNoAuth, "disable auth for Prometheus /metrics endpoint")

	return rv
}

var version = "0.13.0"

func (app *restServerApp) tlsSettings() (*tlsSettings, error) {
	t := &tlsSettings{}
	tlsRequired := app.Server.TLSKey != "" || app.Server.TLSCert != "" || app.Server.TLSCaCert != ""
	if !app.Server.TLS && tlsRequired {
		return nil, errors.New("requires enabled TLS")
	} else if !app.Server.TLS && app.Server.MTLS {
		return nil, errors.New("mTLS requires TLS to be enabled")
	} else if !app.Server.TLS {
		return t, nil
	}
	t.enabled = true

	if app.Server.TLSKey != "" {
		t.key = app.Server.TLSKey
	} else {
		t.key = filepath.Join(app.Server.Path, "private_key")
	}
	if app.Server.TLSCert != "" {
		t.cert = app.Server.TLSCert
	} else {
		t.cert = filepath.Join(app.Server.Path, "public_key")
	}

	if !app.Server.MTLS && app.Server.TLSCaCert != "" {
		return nil, errors.New("CA cert provided but mTLS not enabled")
	}
	if app.Server.MTLS {
		if app.Server.TLSCaCert != "" {
			t.caCert = app.Server.TLSCaCert
		} else {
			t.caCert = filepath.Join(app.Server.Path, "ca_cert")
		}
	}

	return t, nil
}

// returns the address that the app is listening on.
// returns nil if the application hasn't finished starting yet
func (app *restServerApp) ListenerAddress() net.Addr {
	app.listenerAddressMu.Lock()
	defer app.listenerAddressMu.Unlock()
	return app.listenerAddress
}

func (app *restServerApp) runRoot(cmd *cobra.Command, args []string) error {
	log.SetFlags(0)

	log.Printf("Data directory: %s", app.Server.Path)

	if app.CpuProfile != "" {
		f, err := os.Create(app.CpuProfile)
		if err != nil {
			return err
		}
		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()

		log.Println("CPU profiling enabled")
		defer log.Println("Stopped CPU profiling")
	}

	if app.Server.MTLS {
		if app.Server.NoMtlsAuth {
			log.Println("mTLS authentication disabled")
		} else {
			log.Println("mTLS authentication enabled")
			app.Server.NoAuth = false
		}
	}

	if app.Server.NoAuth {
		log.Println("Authentication disabled")
	} else {
		log.Println("Authentication enabled")
	}

	handler, err := restserver.NewHandler(&app.Server)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	if app.Server.AppendOnly {
		log.Println("Append only mode enabled")
	} else {
		log.Println("Append only mode disabled")
	}

	if app.Server.PrivateRepos {
		log.Println("Private repositories enabled")
	} else {
		log.Println("Private repositories disabled")
	}

	tlsSettings, err := app.tlsSettings()
	if err != nil {
		return err
	}

	listener, err := findListener(app.Server.Listen)
	if err != nil {
		return fmt.Errorf("unable to listen: %w", err)
	}

	// set listener address, this is useful for tests
	app.listenerAddressMu.Lock()
	app.listenerAddress = listener.Addr()
	app.listenerAddressMu.Unlock()

	// Configure TLS listener if enabled
	if tlsSettings.enabled {
		tlsConfig, err := tlsSettings.config()
		if err != nil {
			return fmt.Errorf("unable to create TLS config: %w", err)
		}
		log.Printf("TLS enabled, private key %s, pubkey %v", tlsSettings.key, tlsSettings.cert)
		listener = tls.NewListener(listener, tlsConfig)
		if tlsSettings.caCert != "" {
			log.Printf("mTLS enabled, CA cert %s", tlsSettings.caCert)
		}
	}

	srv := &http.Server{
		Handler: handler,
	}

	// run server in background
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := srv.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen and serve returned err: %v", err)
		}
	}()

	// wait until done
	<-app.CmdRoot.Context().Done()

	// gracefully shutdown server
	if err := srv.Shutdown(context.Background()); err != nil {
		return fmt.Errorf("server shutdown returned an err: %w", err)
	}
	<-done

	log.Println("shutdown cleanly")
	return nil
}

func main() {
	// create context to be notified on interrupt or term signal so that we can shutdown cleanly
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := newRestServerApp().CmdRoot.ExecuteContext(ctx); err != nil {
		log.Fatalf("error: %v", err)
	}
}
