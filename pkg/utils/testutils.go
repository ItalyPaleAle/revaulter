//go:build unit

// This file is only built when the "unit" tag is set

package utils

import (
	"io"
	"net/http"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

// Sets appLogger, optionally with a custom buffer as destination
// Returns a function that should be called with "defer" to restore the previous appLogger
func SetAppLogger(appLogger **AppLogger, dest io.Writer) func() {
	prevAppLogger := *appLogger

	if dest == nil {
		dest = os.Stdout
	}
	*appLogger = NewAppLogger("test", dest)
	(*appLogger).SetLogLevel(zerolog.DebugLevel)

	return func() {
		*appLogger = prevAppLogger
	}
}

// Updates the configuration in the viper global object for the test
// Returns a function that should be called with "defer" to restore the previous configuration
func SetTestConfigs(values map[string]any) func() {
	prevConfig := make(map[string]any, len(values))
	for k, v := range values {
		prevConfig[k] = viper.Get(k)
		viper.Set(k, v)
	}

	return func() {
		for k, v := range prevConfig {
			viper.Set(k, v)
		}
	}
}

// RoundTripperTest is a http.RoundTripper that captures the requests and returns the given response.
type RoundTripperTest struct {
	reqCh     chan *http.Request
	responses chan *http.Response
}

func (rtt *RoundTripperTest) SetReqCh(ch chan *http.Request) {
	rtt.reqCh = ch
}

func (rtt *RoundTripperTest) SetResponsesCh(ch chan *http.Response) {
	rtt.responses = ch
}

func (rtt *RoundTripperTest) RoundTrip(r *http.Request) (*http.Response, error) {
	defer func() {
		rtt.reqCh <- r
	}()

	// If there's a response to send in the channel, use that
	// Otherwise create a default one wth the 200 status code
	var resp *http.Response
	select {
	case resp = <-rtt.responses:
		// Nop
	default:
		resp = &http.Response{
			StatusCode: http.StatusOK,
		}
	}

	return resp, nil
}
