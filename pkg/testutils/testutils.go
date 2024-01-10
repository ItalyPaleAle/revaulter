//go:build unit

// This file is only built when the "unit" tag is set

package testutils

import (
	"net/http"
)

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
	// Otherwise create a default one with the 200 status code
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
