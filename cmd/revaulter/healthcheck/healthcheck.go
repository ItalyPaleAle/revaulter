package healthcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/utils"
)

const defaultHealthcheckTimeout = 2500 * time.Millisecond

// Run parses the healthcheck subcommand's args and executes a single probe
// Returns nil when the server's /healthz endpoint replies with a 2xx status, or an error describing the failure
func Run(args []string) error {
	cfg := config.Get()

	flags := pflag.NewFlagSet("healthcheck", pflag.ContinueOnError)

	var (
		server  string
		timeout time.Duration
	)
	flags.StringVarP(&server, "server", "s", "", "Server endpoint")
	flags.DurationVarP(&timeout, "timeout", "t", defaultHealthcheckTimeout, "Request timeout")

	err := flags.Parse(args)
	if err != nil {
		return err
	}

	extraArgs := flags.Args()
	if len(extraArgs) > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(extraArgs, " "))
	}

	// Set default server
	if server == "" {
		server = defaultServer(cfg)
	}

	// Perform the request
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err = Check(ctx, server)
	if err != nil {
		return fmt.Errorf("healthcheck failed: %w", err)
	}

	return nil
}

// Check issues a single GET against `<server>/healthz` and returns nil on a 2xx response
func Check(ctx context.Context, server string) error {
	endpoint := strings.TrimRight(server, "/") + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create healthcheck request: %w", err)
	}

	client := newHTTPClient(req.URL.Scheme == "https")
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("status code %d", res.StatusCode)
	}

	return nil
}

// defaultServer builds the loopback probe URL from the loaded config
// The scheme follows whatever the server is actually listening on so the same binary works under both HTTP and HTTPS
func defaultServer(cfg *config.Config) string {
	scheme := "http"
	if usesTLS(cfg) {
		scheme = "https"
	}

	return scheme + "://localhost:" + strconv.Itoa(cfg.Port)
}

// usesTLS reports whether the server is configured to serve HTTPS
func usesTLS(cfg *config.Config) bool {
	// If the config contains TLS certificate and key, return true
	if cfg.TLSCertPEM != "" && cfg.TLSKeyPEM != "" {
		return true
	}

	// Check if there's a cert key/pair on disk
	tlsPath := cfg.GetTLSPath()
	if tlsPath == "" {
		return false
	}
	ok, err := utils.FileExists(filepath.Join(tlsPath, config.TLSCertFile))
	if err != nil || !ok {
		return false
	}
	ok, err = utils.FileExists(filepath.Join(tlsPath, config.TLSKeyFile))
	if err != nil || !ok {
		return false
	}

	// We have certs on disk
	// Note that we don't validate them here, we just accept that they are set
	return true
}

// newHTTPClient builds the HTTP client used to issue the healthcheck probe
func newHTTPClient(skipTLSVerification bool) *http.Client {
	//nolint:forcetypeassert
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if skipTLSVerification {
		transport.TLSClientConfig = &tls.Config{
			//nolint:gosec // Intentional: probe is loopback-only and must work with self-signed certs
			InsecureSkipVerify: true,
		}
	}

	return &http.Client{
		Transport: transport,
	}
}
