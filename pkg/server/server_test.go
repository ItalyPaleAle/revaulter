package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/keyvault"
	"github.com/italypaleale/revaulter/pkg/utils"
	"github.com/italypaleale/revaulter/pkg/utils/bufconn"
)

const (
	// Servers are started on in-memory listeners so these ports aren't actually used for TCP sockets
	testServerPort  = 5701
	testMetricsPort = 5702

	// Size for the in-memory buffer for bufconn
	bufconnBufSize = 1 << 20 // 1MB

	jsonContentType = "application/json; charset=utf-8"
)

func TestMain(m *testing.M) {
	keysBase, _ := hex.DecodeString("93df391229720f4b8e6567de9acc34f12614c3929497836a28e37878897c13fa")
	csk, _ := jwk.FromRaw(keysBase)
	cek, _ := jwk.FromRaw(keysBase[0:16])

	defer utils.SetTestConfigs(map[string]any{
		config.KeyLogLevel:                    "info",
		config.KeyPort:                        testServerPort,
		config.KeyBind:                        "127.0.0.1",
		config.KeySessionTimeout:              5 * time.Minute,
		config.KeyRequestTimeout:              5 * time.Minute,
		config.KeyWebhookUrl:                  "http://test.local",
		config.KeyEnableMetrics:               false,
		config.KeyMetricsBind:                 "127.0.0.1",
		config.KeyMetricsPort:                 testMetricsPort,
		config.KeyAzureClientId:               "azure-client-id",
		config.KeyAzureTenantId:               "azure-tenant-id",
		config.KeyInternalTokenSigningKey:     "hello-world",
		config.KeyInternalCookieSigningKey:    csk,
		config.KeyInternalCookieEncryptionKey: cek,
	})()

	gin.SetMode(gin.ReleaseMode)

	os.Exit(m.Run())
}

func TestServerLifecycle(t *testing.T) {
	testFn := func(metricsEnabled bool) func(t *testing.T) {
		return func(t *testing.T) {
			defer utils.SetTestConfigs(map[string]any{
				config.KeyEnableMetrics: metricsEnabled,
			})()

			// Create the server
			// This will create in-memory listeners with bufconn too
			srv, _, cleanup := newTestServer(t, nil, nil)
			require.NotNil(t, srv)
			defer cleanup()
			stopServerFn := startTestServer(t, srv)
			defer stopServerFn(t)

			// Make a request to the /healthz endpoint in the app server
			appClient := clientForListener(srv.appListener)
			reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer reqCancel()
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
				fmt.Sprintf("https://localhost:%d/healthz", testServerPort), nil)
			require.NoError(t, err)
			res, err := appClient.Do(req)
			require.NoError(t, err)
			defer closeBody(res)

			healthzRes, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			require.NotEmpty(t, healthzRes)

			// Make a request to the /healthz endpoint in the metrics server
			if metricsEnabled {
				metricsClient := clientForListener(srv.metricsListener)
				reqCtx, reqCancel = context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				req, err = http.NewRequestWithContext(reqCtx, http.MethodGet,
					fmt.Sprintf("http://localhost:%d/healthz", testMetricsPort), nil)
				require.NoError(t, err)
				res, err = metricsClient.Do(req)
				require.NoError(t, err)
				defer closeBody(res)

				resBody, err := io.ReadAll(res.Body)
				require.NoError(t, err)
				require.Equal(t, healthzRes, resBody)
			}
		}
	}

	t.Run("run the server without metrics", testFn(false))

	t.Run("run the server with metrics enabled", testFn(true))
}

func TestServerAppRoutes(t *testing.T) {
	var accessTokenCookie *http.Cookie

	// Create a roundtripper that captures the requests
	rtt := &utils.RoundTripperTest{}

	// Create a mock webhook
	webhookRequests := make(chan *utils.WebhookRequest, 1)

	// Create the server
	// This will create in-memory listeners with bufconn too
	srv, logBuf, cleanup := newTestServer(t, &mockWebhook{requests: webhookRequests}, rtt)
	require.NotNil(t, srv)
	defer cleanup()
	stopServerFn := startTestServer(t, srv)
	defer stopServerFn(t)
	appClient := clientForListener(srv.appListener)

	// Mock the Key Vault client
	srv.kvClientFactory = func(accessToken string, expiration time.Time) keyvault.Client {
		return &mockKVClient{}
	}

	// Add a route group for routes specific to some tests
	testRoutes := srv.appRouter.Group("/_test")

	// Test the healthz endpoints
	t.Run("healthz", func(t *testing.T) {
		// Make a request to the /healthz endpoint
		reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			fmt.Sprintf("https://localhost:%d/healthz", testServerPort), nil)
		require.NoError(t, err)
		res, err := appClient.Do(req)
		require.NoError(t, err)
		defer closeBody(res)

		// Check the response
		require.Equal(t, "application/json", res.Header.Get("content-type"))

		body := map[string]any{}
		err = json.NewDecoder(res.Body).Decode(&body)
		require.NoError(t, err)
		require.NotEmpty(t, body)
		require.Equal(t, "ok", body["status"])

		// Reset the log buffer
		logBuf.Reset()
	})

	// Test the auth routes
	t.Run("auth", func(t *testing.T) {
		var (
			authState       string
			authStateCookie *http.Cookie
		)

		// Make a request to the /auth/signin endpoint
		t.Run("signin", func(t *testing.T) {
			reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer reqCancel()
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
				fmt.Sprintf("https://localhost:%d/auth/signin", testServerPort), nil)
			require.NoError(t, err)
			res, err := appClient.Do(req)
			require.NoError(t, err)
			defer closeBody(res)

			// Ensure the redirect is present
			require.Equal(t, http.StatusTemporaryRedirect, res.StatusCode)

			loc := res.Header.Get("location")
			require.NotEmpty(t, loc)

			locURL, err := url.Parse(loc)
			require.NoError(t, err)

			assert.True(t, strings.HasPrefix(loc, "https://login.microsoftonline.com/azure-tenant-id/oauth2/v2.0/authorize"))
			assert.Equal(t, "azure-client-id", locURL.Query().Get("client_id"))
			assert.Equal(t, "https://localhost:"+strconv.Itoa(testServerPort)+"/auth/confirm", locURL.Query().Get("redirect_uri"))
			assert.Equal(t, "https://vault.azure.net/user_impersonation", locURL.Query().Get("scope"))
			assert.NotEmpty(t, locURL.Query().Get("code_challenge"))

			authState = locURL.Query().Get("state")
			require.NotEmpty(t, authState)

			// Ensure the cookie is present
			cookies := res.Cookies()
			require.NotEmpty(t, cookies)
			require.Len(t, cookies, 1)
			require.NotNil(t, cookies[0])

			require.Equal(t, "_auth_state", cookies[0].Name)
			require.Equal(t, "/auth", cookies[0].Path)
			require.NoError(t, cookies[0].Valid())
			require.NotEmpty(t, cookies[0].Value)
			require.Greater(t, cookies[0].MaxAge, 1) //nolint:testifylint
			authStateCookie = cookies[0]
		})

		t.Run("confirm", func(t *testing.T) {
			// Helper function that ensures the auth state cookie is unset in case of errors
			ensureAuthStateCookieUnset := func(t *testing.T, res *http.Response) {
				var found bool
				for _, cookie := range res.Cookies() {
					if cookie.Name != "_auth_state" {
						continue
					}

					found = true
					require.NoError(t, cookie.Valid())
					require.Empty(t, cookie.Value)
					require.Equal(t, -1, cookie.MaxAge)
					require.Equal(t, "/auth", cookie.Path)
				}

				require.True(t, found)
			}

			t.Run("Missing code", func(t *testing.T) {
				reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
					fmt.Sprintf("https://localhost:%d/auth/confirm", testServerPort), nil)
				require.NoError(t, err)
				res, err := appClient.Do(req)
				require.NoError(t, err)
				defer closeBody(res)

				assertResponseError(t, res, http.StatusBadRequest, "Parameter code is missing in the request")
			})

			t.Run("Missing state", func(t *testing.T) {
				// Reset the log buffer before starting
				logBuf.Reset()

				reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
					fmt.Sprintf("https://localhost:%d/auth/confirm?code=foo", testServerPort), nil)
				require.NoError(t, err)
				res, err := appClient.Do(req)
				require.NoError(t, err)
				defer closeBody(res)

				assertResponseError(t, res, http.StatusBadRequest, "Parameter state is missing in the request")

				// Ensure that the logs do not contain the code and state
				assert.Contains(t, logBuf.String(), `"status":400,"method":"GET","path":"/auth/confirm?code***",`)
			})

			t.Run("Missing auth state cookie", func(t *testing.T) {
				reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
					fmt.Sprintf("https://localhost:%d/auth/confirm?code=foo&state=bar", testServerPort), nil)
				require.NoError(t, err)
				res, err := appClient.Do(req)
				require.NoError(t, err)
				defer closeBody(res)

				assertResponseError(t, res, http.StatusBadRequest, "Auth state cookie is missing or invalid")
			})

			t.Run("Invalid auth state cookie", func(t *testing.T) {
				reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				// The state parameter in the header does not match what's in the cookie
				req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
					fmt.Sprintf("https://localhost:%d/auth/confirm?code=foo&state=_notvalid", testServerPort), nil)
				require.NoError(t, err)
				req.AddCookie(authStateCookie)

				res, err := appClient.Do(req)
				require.NoError(t, err)
				defer closeBody(res)

				assertResponseError(t, res, http.StatusBadRequest, "The state token could not be validated")
				ensureAuthStateCookieUnset(t, res)
			})

			t.Run("Exchange for access token", func(t *testing.T) {
				reqCh := make(chan *http.Request, 1)
				responsesCh := make(chan *http.Response, 1)
				responsesCh <- &http.Response{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(strings.NewReader(`{"token_type":"Bearer","scope":"https://vault.azure.net/user_impersonation","access_token":"my-access-token","expires_in":3600}`)),
				}
				rtt.SetReqCh(reqCh)
				rtt.SetResponsesCh(responsesCh)
				defer func() {
					rtt.SetReqCh(nil)
					rtt.SetResponsesCh(nil)
				}()

				reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
					fmt.Sprintf("https://localhost:%d/auth/confirm?code=auth-code&state=%s", testServerPort, authState), nil)
				require.NoError(t, err)
				req.AddCookie(authStateCookie)

				res, err := appClient.Do(req)
				require.NoError(t, err)
				defer closeBody(res)

				// Ensure the redirect is present
				require.Equal(t, http.StatusTemporaryRedirect, res.StatusCode)

				loc := res.Header.Get("location")
				require.Equal(t, fmt.Sprintf("https://localhost:%d", testServerPort), loc)

				// Ensure the cookies are present
				// Should both set _at and reset _auth_state
				cookies := res.Cookies()
				require.NotEmpty(t, cookies)
				require.Len(t, cookies, 2)

				for _, cookie := range cookies {
					require.NotNil(t, cookie)
					switch cookie.Name {
					case "_at":
						require.NoError(t, cookie.Valid())
						require.NotEmpty(t, cookie.Value)
						require.Equal(t, int(viper.GetDuration(config.KeySessionTimeout).Seconds()), cookie.MaxAge)
						require.Equal(t, "/", cookie.Path)
						accessTokenCookie = cookie
					case "_auth_state":
						require.NoError(t, cookie.Valid())
						require.Empty(t, cookie.Value)
						require.Equal(t, -1, cookie.MaxAge)
						require.Equal(t, "/auth", cookie.Path)
						authStateCookie = nil
					default:
						t.Fatal("Found unexpected cookie:", cookie.Name)
					}
				}
			})
		})

		// Reset the log buffer
		logBuf.Reset()
	})

	// If we don't have an access token, stop here since we can't test the next routes
	require.NotEmpty(t, accessTokenCookie, "Cannot continue tests without an access token")

	t.Run("auth middleware", func(t *testing.T) {
		// Add routes specifically to test the auth middleware
		testRoutes.GET("/auth",
			srv.AccessTokenMiddleware(AccessTokenMiddlewareOpts{Required: true}),
			func(c *gin.Context) {
				c.Status(http.StatusNoContent)
			},
		)
		testRoutes.GET("/auth-header",
			srv.AccessTokenMiddleware(AccessTokenMiddlewareOpts{Required: true, AllowAccessTokenInHeader: true}),
			func(c *gin.Context) {
				c.Status(http.StatusNoContent)
			},
		)

		authTestFn := func(success bool, path string, modifier func(req *http.Request)) func(t *testing.T) {
			return func(t *testing.T) {
				reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
					fmt.Sprintf("https://localhost:%d/_test/%s", testServerPort, path), nil)
				require.NoError(t, err)
				if modifier != nil {
					modifier(req)
				}

				res, err := appClient.Do(req)
				require.NoError(t, err)
				defer closeBody(res)

				if success {
					require.Equal(t, http.StatusNoContent, res.StatusCode)
				} else {
					require.Equal(t, http.StatusUnauthorized, res.StatusCode)
				}
			}
		}

		t.Run("successful auth with cookie", authTestFn(true, "auth", func(req *http.Request) {
			req.AddCookie(accessTokenCookie)
		}))

		t.Run("successful auth with header", authTestFn(true, "auth-header", func(req *http.Request) {
			req.Header.Set("authorization", "Bearer "+accessTokenCookie.Value)
		}))

		t.Run("successful auth with cookie when header is allowed too", authTestFn(true, "auth-header", func(req *http.Request) {
			req.AddCookie(accessTokenCookie)
		}))

		t.Run("missing access token", authTestFn(false, "auth", nil))

		t.Run("access token in header not allowed by route", authTestFn(false, "auth", func(req *http.Request) {
			req.Header.Set("authorization", "Bearer "+accessTokenCookie.Value)
		}))

		t.Run("missing Bearer prefix in header", authTestFn(false, "auth-header", func(req *http.Request) {
			req.Header.Set("authorization", accessTokenCookie.Value)
		}))
	})

	t.Run("Operations and APIs", func(t *testing.T) {
		t.Run("List API returns no item", func(t *testing.T) {
			reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer reqCancel()
			req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
				fmt.Sprintf("https://localhost:%d/api/list", testServerPort), nil)
			require.NoError(t, err)
			req.AddCookie(accessTokenCookie)

			res, err := appClient.Do(req)
			require.NoError(t, err)
			defer closeBody(res)

			// Response should be an empty JSON array
			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, jsonContentType, res.Header.Get("content-type"))

			body, err := io.ReadAll(res.Body)
			require.NoError(t, err)
			require.Equal(t, "[]", string(body))
		})

		listSubscribeCtx, listSubscribeCancel := context.WithCancel(context.Background())
		defer listSubscribeCancel()
		listSubscribeCh := make(chan *requestStatePublic)
		t.Run("Subscribe to list API stream", func(t *testing.T) {
			req, err := http.NewRequestWithContext(listSubscribeCtx, http.MethodGet,
				fmt.Sprintf("https://localhost:%d/api/list", testServerPort), nil)
			require.NoError(t, err)
			req.Header.Set("accept", ndJSONContentType)
			req.AddCookie(accessTokenCookie)

			// Do not call defer closeBody(res) here because we want to continue reading from the stream after the test is done
			//nolint:bodyclose
			res, err := appClient.Do(req)
			require.NoError(t, err)

			require.Equal(t, http.StatusOK, res.StatusCode)
			require.Equal(t, ndJSONContentType, res.Header.Get("content-type"))

			go func() {
				defer closeBody(res)

				dec := json.NewDecoder(res.Body)
				for {
					var val requestStatePublic
					decErr := dec.Decode(&val)
					if decErr == nil {
						listSubscribeCh <- &val
					} else if errors.Is(decErr, io.EOF) || errors.Is(decErr, context.Canceled) {
						break
					} else {
						panic("Unexpected error from list API stream: " + decErr.Error())
					}
				}
				close(listSubscribeCh)
			}()
		})

		// If the test failed at this stage, we need to abort
		require.False(t, t.Failed(), "Cannot continue tests without a list subscription")

		createRequestFn := func(reqDataFn func(*operationRequest), resultFn func(stateID string)) func(t *testing.T) {
			return func(t *testing.T) {
				reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				reqData := &operationRequest{
					Vault:     "testvault",
					KeyId:     "testkey",
					Algorithm: "RSA-OAEP",
					Value:     base64.RawURLEncoding.EncodeToString([]byte("hello world")),
				}
				if reqDataFn != nil {
					reqDataFn(reqData)
				}
				reqBody, _ := json.Marshal(reqData)
				req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
					fmt.Sprintf("https://localhost:%d/request/encrypt", testServerPort),
					bytes.NewReader(reqBody),
				)
				require.NoError(t, err)
				req.Header.Set("content-type", jsonContentType)

				res, err := appClient.Do(req)
				require.NoError(t, err)
				defer closeBody(res)

				// Response should contain the operation ID
				require.Equal(t, http.StatusAccepted, res.StatusCode)
				require.Equal(t, jsonContentType, res.Header.Get("content-type"))

				resData := operationResponse{}
				err = json.NewDecoder(res.Body).Decode(&resData)
				require.NoError(t, err)
				assert.True(t, resData.Pending)
				assert.False(t, resData.Done)
				assert.False(t, resData.Failed)
				assert.NotEmpty(t, resData.State)

				// The list channel should now receive the new request
				select {
				case <-time.After(time.Second):
					t.Fatalf("Did not receive item in list within 1s: %s", resData.State)
				case item := <-listSubscribeCh:
					require.NotNil(t, item)
					require.Equal(t, resData.State, item.State)
					assert.Equal(t, "pending", item.Status)
					assert.Equal(t, "encrypt", item.Operation)
					assert.Equal(t, "testvault", item.VaultName)
					assert.Equal(t, "testkey", item.KeyId)

					// Request date should be approximately now or a few seconds ago
					now := time.Now().Unix()
					assert.LessOrEqual(t, item.Date, now)
					assert.Greater(t, item.Date, now-5)

					// Item should have the correct expiration date
					expectTimeoutSeconds := int64(viper.GetDuration(config.KeyRequestTimeout).Seconds())
					if timeout, ok := reqData.Timeout.(string); ok && timeout != "" {
						dur, err := time.ParseDuration(timeout)
						require.NoError(t, err)
						expectTimeoutSeconds = int64(dur.Seconds())
					}
					assert.Equal(t, item.Date+expectTimeoutSeconds, item.Expiry)
				}

				if resultFn != nil {
					resultFn(resData.State)
				}

				// Webhook should have been invoked
				select {
				case <-time.After(100 * time.Millisecond):
					t.Fatalf("Did not receive webhook before timeout: %s", resData.State)
				case msg := <-webhookRequests:
					require.NotNil(t, msg)
					assert.Equal(t, resData.State, msg.StateId)
					assert.Equal(t, "encrypt", msg.OperationName)
					assert.Equal(t, reqData.Note, msg.Note)
					assert.Equal(t, "testvault", msg.Vault)
					assert.Equal(t, "testkey", msg.KeyId)
					// IP of caller is always 1.2.3.4 in bufconn
					assert.Equal(t, "1.2.3.4", msg.Requestor)
				}
			}
		}

		var stateIDs [6]string
		t.Run("Create 5 requests", func(t *testing.T) {
			for i := 0; i < 5; i++ {
				t.Run("request "+strconv.Itoa(i), createRequestFn(nil, func(stateID string) {
					stateIDs[i] = stateID
				}))
			}
		})

		t.Run("Create request that expires in 1s", createRequestFn(
			func(or *operationRequest) {
				// Minimum is 1s
				or.Timeout = "1s"
			},
			func(stateID string) {
				stateIDs[5] = stateID
			},
		))

		t.Log("State IDs", stateIDs)

		var responsesChs [6]chan *struct {
			state  string
			status int
			res    map[string]any
			reqID  int
		}
		subscribeToResponseFn := func(t *testing.T, stateID int, reqID int) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
				fmt.Sprintf("https://localhost:%d/request/result/%s", testServerPort, stateIDs[stateID]), nil)
			require.NoError(t, err)
			req.Header.Set("content-type", jsonContentType)

			if responsesChs[stateID] == nil {
				responsesChs[stateID] = make(chan *struct {
					state  string
					status int
					res    map[string]any
					reqID  int
				}, 1)
			}

			go func() {
				res, err := appClient.Do(req)
				if err != nil {
					panic("Failed to make request: " + err.Error())
				}
				defer closeBody(res)

				var resData map[string]any
				err = json.NewDecoder(res.Body).Decode(&resData)
				if err != nil {
					panic("Failed to decode JSON response: " + err.Error())
				}

				responsesChs[stateID] <- &struct {
					state  string
					status int
					res    map[string]any
					reqID  int
				}{
					state:  stateIDs[stateID],
					status: res.StatusCode,
					res:    resData,
					reqID:  reqID,
				}
			}()
		}

		t.Run("Subscribe to responses", func(t *testing.T) {
			t.Run("Subscribe to request 0", func(t *testing.T) {
				subscribeToResponseFn(t, 0, 0)
			})

			t.Run("Subscribe to request 1 multiple times", func(t *testing.T) {
				// Subscribe to state ID 1; there should be no signal at this point
				subscribeToResponseFn(t, 1, 1)
				select {
				case <-time.After(750 * time.Millisecond):
					// All good
				case data := <-responsesChs[1]:
					t.Fatal("Received response when it was not expected", data)
				}

				// Subscribing to state ID 1 again should cause the first request to be interrupted
				subscribeToResponseFn(t, 1, 2)
				select {
				case <-time.After(750 * time.Millisecond):
					t.Fatal("Did not receive a response in time")
				case data := <-responsesChs[1]:
					require.Equal(t, 1, data.reqID)
					assert.Equal(t, http.StatusAccepted, data.status)
					assert.Equal(t, map[string]any{
						"state":   stateIDs[1],
						"pending": true,
					}, data.res)
				}

				// Repeat
				subscribeToResponseFn(t, 1, 3)
				select {
				case <-time.After(750 * time.Millisecond):
					t.Fatal("Did not receive a response in time")
				case data := <-responsesChs[1]:
					require.Equal(t, 2, data.reqID)
					assert.Equal(t, http.StatusAccepted, data.status)
					assert.Equal(t, map[string]any{
						"state":   stateIDs[1],
						"pending": true,
					}, data.res)
				}
			})

			t.Run("Subscribe to request 5", func(t *testing.T) {
				subscribeToResponseFn(t, 5, 100)
			})
		})

		t.Run("Request 5 should expire", func(t *testing.T) {
			// Should expire
			select {
			// This gives it 1.5 seconds because the request expires after 1s
			case <-time.After(1500 * time.Millisecond):
				t.Fatal("Did not receive a response in time")
			case data := <-responsesChs[5]:
				require.Equal(t, 100, data.reqID)
				assert.Equal(t, http.StatusConflict, data.status)
				assert.Equal(t, map[string]any{
					"state":  stateIDs[5],
					"failed": true,
				}, data.res)
			}

			// The list channel should receive the notification
			select {
			case <-time.After(500 * time.Millisecond):
				t.Fatal("Did not receive updated item in list within 500ms")
			case item := <-listSubscribeCh:
				require.NotNil(t, item)
				require.Equal(t, stateIDs[5], item.State)
				assert.Equal(t, "removed", item.Status)
			}
		})

		t.Run("Complete operations", func(t *testing.T) {
			completeOperationFn := func(t *testing.T, reqCtx context.Context, reqData *confirmRequest) *http.Response {
				t.Helper()

				reqBody, _ := json.Marshal(reqData)
				req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
					fmt.Sprintf("https://localhost:%d/api/confirm", testServerPort),
					bytes.NewReader(reqBody),
				)
				require.NoError(t, err)
				req.AddCookie(accessTokenCookie)
				req.Header.Set("content-type", jsonContentType)

				res, err := appClient.Do(req)
				require.NoError(t, err)

				return res
			}

			t.Run("Cannot have both confirm and cancel", func(t *testing.T) {
				reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				// False positive - body is closed
				//nolint:bodyclose
				res := completeOperationFn(t, reqCtx, &confirmRequest{
					Cancel:  true,
					Confirm: true,
					StateId: stateIDs[0],
				})
				defer closeBody(res)

				assertResponseError(t, res, http.StatusBadRequest, "One and only one of confirm and cancel must be set to true in the body")
			})

			t.Run("Operation not found", func(t *testing.T) {
				reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				// False positive - body is closed
				//nolint:bodyclose
				res := completeOperationFn(t, reqCtx, &confirmRequest{
					Confirm: true,
					StateId: "not-found",
				})
				defer closeBody(res)

				assertResponseError(t, res, http.StatusBadRequest, "State not found or expired")
			})

			t.Run("Operation has expired", func(t *testing.T) {
				reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				// False positive - body is closed
				//nolint:bodyclose
				res := completeOperationFn(t, reqCtx, &confirmRequest{
					Confirm: true,
					StateId: stateIDs[5],
				})
				defer closeBody(res)

				assertResponseError(t, res, http.StatusBadRequest, "State not found or expired")
			})

			t.Run("Cancel operation 0", func(t *testing.T) {
				reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				// False positive - body is closed
				//nolint:bodyclose
				res := completeOperationFn(t, reqCtx, &confirmRequest{
					Cancel:  true,
					StateId: stateIDs[0],
				})
				defer closeBody(res)

				// Response should be a JSON object indicating cancellation
				require.Equal(t, http.StatusOK, res.StatusCode)
				require.Equal(t, jsonContentType, res.Header.Get("content-type"))

				body, err := io.ReadAll(res.Body)
				require.NoError(t, err)
				require.Equal(t, `{"canceled":true}`, string(body))

				// Should receive the result in responsesChs[0]
				select {
				case <-time.After(500 * time.Millisecond):
					t.Fatal("Did not receive a response in time")
				case data := <-responsesChs[0]:
					require.Equal(t, 0, data.reqID)
					assert.Equal(t, http.StatusConflict, data.status)
					assert.Equal(t, map[string]any{
						"state":  stateIDs[0],
						"failed": true,
					}, data.res)
				}

				// The list channel should receive the notification
				select {
				case <-time.After(500 * time.Millisecond):
					t.Fatal("Did not receive updated item in list within 500ms")
				case item := <-listSubscribeCh:
					require.NotNil(t, item)
					require.Equal(t, stateIDs[0], item.State)
					assert.Equal(t, "removed", item.Status)
				}
			})

			t.Run("Confirm operation 1", func(t *testing.T) {
				reqCtx, reqCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer reqCancel()
				res := completeOperationFn(t, reqCtx, &confirmRequest{
					Confirm: true,
					StateId: stateIDs[1],
				})
				defer closeBody(res)

				// Response should be a JSON object indicating confirmation
				require.Equal(t, http.StatusOK, res.StatusCode)
				require.Equal(t, jsonContentType, res.Header.Get("content-type"))

				body, err := io.ReadAll(res.Body)
				require.NoError(t, err)
				require.Equal(t, `{"confirmed":true}`, string(body))

				// Should receive the result in responsesChs[0]
				select {
				case <-time.After(500 * time.Millisecond):
					t.Fatal("Did not receive a response in time")
				case data := <-responsesChs[1]:
					// This was request 3
					require.Equal(t, 3, data.reqID)
					assert.Equal(t, http.StatusOK, data.status)
					assert.Equal(t, map[string]any{
						"done": true,
						"response": map[string]any{
							"data": base64.StdEncoding.EncodeToString([]byte("hello world")),
						},
						"state": stateIDs[1],
					}, data.res)
				}

				// The list channel should receive the notification
				select {
				case <-time.After(500 * time.Millisecond):
					t.Fatal("Did not receive updated item in list within 500ms")
				case item := <-listSubscribeCh:
					require.NotNil(t, item)
					require.Equal(t, stateIDs[1], item.State)
					assert.Equal(t, "removed", item.Status)
				}
			})
		})

		t.Run("Stop list subscription", func(t *testing.T) {
			// Canceling the context should stop the request
			listSubscribeCancel()
			select {
			case <-time.After(time.Second):
				t.Fatal("Did not receive signal within 1s")
			case _, more := <-listSubscribeCh:
				require.False(t, more)
			}
		})
	})
}

func newTestServer(t *testing.T, wh *mockWebhook, httpClientTransport http.RoundTripper) (*Server, *bytes.Buffer, func()) {
	t.Helper()

	logBuf := &bytes.Buffer{}
	logDest := io.MultiWriter(os.Stderr, logBuf)

	log := utils.NewAppLogger("test", zerolog.SyncWriter(logDest))
	if wh == nil {
		wh = &mockWebhook{}
	}

	cert, key, err := getSelfSignedTLSCredentials()
	require.NoError(t, err, "cannot get TLS credentials")

	cleanup := utils.SetTestConfigs(map[string]any{
		config.KeyTLSCertPEM: cert,
		config.KeyTLSKeyPEM:  key,
	})

	srv, err := NewServer(log, wh)
	require.NoError(t, err)

	srv.appListener = bufconn.Listen(bufconnBufSize)
	srv.metricsListener = bufconn.Listen(bufconnBufSize)

	if httpClientTransport != nil {
		srv.httpClient.Transport = httpClientTransport
	}

	return srv, logBuf, cleanup
}

func startTestServer(t *testing.T, srv *Server) func(t *testing.T) {
	t.Helper()

	// Start the server in a background goroutine
	srvCtx, srvCancel := context.WithCancel(context.Background())
	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- srv.Run(srvCtx)
	}()

	// Ensure the server has started and there's no error
	// This may report false positives if the server just takes longer to start, but we'll still catch those errors later on
	select {
	case <-time.After(100 * time.Millisecond):
		// all good
	case err := <-startErrCh:
		t.Fatalf("Received an unexpected error in startErrCh: %v", err)
	}

	// Return a function to tear down the test server, which must be invoked at the end of the test
	return func(t *testing.T) {
		t.Helper()

		// Shutdown the server
		srvCancel()

		// At the end of the test, there should be no error
		require.NoError(t, <-startErrCh, "received an unexpected error in startErrCh")
	}
}

func clientForListener(ln net.Listener) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	//nolint:gosec
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	transport.DialContext = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		bl, ok := ln.(*bufconn.Listener)
		if !ok {
			return nil, errors.New("failed to cast listener to bufconn.Listener")
		}
		return bl.DialContext(ctx)
	}

	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func getSelfSignedTLSCredentials() (certPem []byte, keyPem []byte, err error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	certDer, err := x509.CreateCertificate(rand.Reader, &template, &template, pk.Public(), pk)
	if err != nil {
		return nil, nil, err
	}
	certPem = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer})

	keyDer, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		return nil, nil, err
	}

	keyPem = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer})

	return certPem, keyPem, nil
}

func assertResponseError(t *testing.T, res *http.Response, expectStatusCode int, expectErr string) {
	t.Helper()

	require.Equal(t, expectStatusCode, res.StatusCode, "Response has an unexpected status code")
	require.Equal(t, jsonContentType, res.Header.Get("content-type"), "Content-Type header is invalid")

	data := struct {
		Error string `json:"error"`
	}{}
	err := json.NewDecoder(res.Body).Decode(&data)
	require.NoError(t, err, "Error parsing response body as JSON")

	require.Equal(t, expectErr, data.Error, "Error message does not match")
}

// mockWebhook implements the Webhook interface
type mockWebhook struct {
	requests chan *utils.WebhookRequest
}

func (w mockWebhook) SendWebhook(_ context.Context, data *utils.WebhookRequest) error {
	if w.requests != nil {
		w.requests <- data
	}
	return nil
}

func (w mockWebhook) SetBaseURL(val string) {
	// Nop
}

// Closes a HTTP response body making sure to drain it first
// Normally invoked as a defer'd function
func closeBody(res *http.Response) {
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
}

// mockKVClient implements the keyvault.Client interface
type mockKVClient struct{}

func (kv *mockKVClient) Encrypt(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationParameters) (*keyvault.KeyVaultEncryptResponse, error) {
	res := &keyvault.KeyVaultEncryptResponse{
		Data: params.Value,
	}
	res.SetKeyID(keyName + "/" + keyVersion)
	return res, nil
}

func (kv *mockKVClient) Decrypt(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationParameters) (*keyvault.KeyVaultDecryptResponse, error) {
	res := &keyvault.KeyVaultDecryptResponse{
		Data: params.Value,
	}
	res.SetKeyID(keyName + "/" + keyVersion)
	return res, nil
}

func (kv *mockKVClient) WrapKey(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationParameters) (*keyvault.KeyVaultEncryptResponse, error) {
	res := &keyvault.KeyVaultEncryptResponse{
		Data: params.Value,
	}
	res.SetKeyID(keyName + "/" + keyVersion)
	return res, nil
}

func (kv *mockKVClient) UnwrapKey(ctx context.Context, vault, keyName, keyVersion string, params azkeys.KeyOperationParameters) (*keyvault.KeyVaultDecryptResponse, error) {
	res := &keyvault.KeyVaultDecryptResponse{
		Data: params.Value,
	}
	res.SetKeyID(keyName + "/" + keyVersion)
	return res, nil
}

func (kv *mockKVClient) Sign(ctx context.Context, vault, keyName, keyVersion string, params azkeys.SignParameters) (*keyvault.KeyVaultSignResponse, error) {
	res := &keyvault.KeyVaultSignResponse{
		Data: params.Value,
	}
	res.SetKeyID(keyName + "/" + keyVersion)
	return res, nil
}

func (kv *mockKVClient) Verify(ctx context.Context, vault, keyName, keyVersion string, params azkeys.VerifyParameters) (*keyvault.KeyVaultVerifyResponse, error) {
	res := &keyvault.KeyVaultVerifyResponse{
		Valid: true,
	}
	res.SetKeyID(keyName + "/" + keyVersion)
	return res, nil
}
