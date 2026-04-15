package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	location "github.com/gin-contrib/location/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-chi/httprate"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/italypaleale/go-kit/eventqueue"
	slogkit "github.com/italypaleale/go-kit/slog"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdkTrace "go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/db"
	"github.com/italypaleale/revaulter/pkg/metrics"
	"github.com/italypaleale/revaulter/pkg/utils/broker"
	"github.com/italypaleale/revaulter/pkg/utils/logging"
	"github.com/italypaleale/revaulter/pkg/utils/webhook"
)

const (
	ndJSONContentType = "application/x-ndjson"
	jsonContentType   = "application/json; charset=utf-8"
)

// These variables are overwritten in e2e_routes_testbuild when building for e2e tests
var (
	// List of test routes
	testRoutes []func(s *Server, r gin.IRouter)
	// Rate limit for CLI request creation
	// 200 req/m
	requestRateLimit = 200
	// Rate limit for auth endpoints
	// 30 req/m
	authRateLimitRPM = 30
)

// Server is the server based on Gin
type Server struct {
	appRouter  *gin.Engine
	httpClient *http.Client
	lock       sync.RWMutex
	webhook    webhook.Webhook
	metrics    *metrics.RevaulterMetrics

	// Subscribers for pending request list updates
	pubsub *broker.Broker[*db.V2RequestListItem]
	// Subscriptions to watch request status changes
	subs map[string]chan struct{}

	// Delayed work for request expiry and record deletion
	requestExpiryQueue *eventqueue.Processor[string, requestExpiryEvent]
	deleteQueue        *eventqueue.Processor[string, deleteEvent]

	// Database and request store
	db           *db.DB
	requestStore *db.RequestStore
	authStore    *db.AuthStore
	webAuthn     *webauthnlib.WebAuthn

	// Per-user rate limiter for wrapped primary key delivery
	// Protects delivery of the wrapped root-key blob to a WebAuthn-authenticated client
	// and reduces abuse of the password-gated unwrap flow
	wrappedKeyLimiter *httprate.RateLimiter

	// Servers
	appSrv *http.Server

	// Method that forces a reload of TLS certificates from disk
	tlsCertWatchFn tlsCertWatchFn

	// TLS configuration for the app server
	tlsConfig *tls.Config

	tracer  *sdkTrace.TracerProvider
	running atomic.Bool
	wg      sync.WaitGroup

	// Listeners for the app and metrics servers
	// These can be used for testing without having to start an actual TCP listener
	appListener net.Listener
}

// NewServerOpts contains options for the NewServer method
type NewServerOpts struct {
	Log           *slog.Logger
	Webhook       webhook.Webhook
	Metrics       *metrics.RevaulterMetrics
	TraceExporter sdkTrace.SpanExporter
	DB            *db.DB
	RequestStore  *db.RequestStore
	AuthStore     *db.AuthStore
}

// NewServer creates a new Server object and initializes it
func NewServer(opts NewServerOpts) (*Server, error) {
	// Create the HTTP client
	// Update its transport to include tracing information
	httpClient := &http.Client{
		Timeout: 15 * time.Second,
	}
	httpClient.Transport = otelhttp.NewTransport(httpClient.Transport)

	s := &Server{
		subs:         map[string]chan struct{}{},
		pubsub:       broker.NewBroker[*db.V2RequestListItem](),
		webhook:      opts.Webhook,
		metrics:      opts.Metrics,
		db:           opts.DB,
		authStore:    opts.AuthStore,
		requestStore: opts.RequestStore,

		httpClient: httpClient,

		// Throttle wrapped primary key delivery to 5 successful logins per hour per user
		wrappedKeyLimiter: httprate.NewRateLimiter(5, time.Hour),
	}

	// Create the eventqueue processors for performing garbage collection
	s.requestExpiryQueue = eventqueue.NewProcessor(eventqueue.Options[string, requestExpiryEvent]{
		ExecuteFn: s.executeRequestExpiryEvent,
	})
	s.deleteQueue = eventqueue.NewProcessor(eventqueue.Options[string, deleteEvent]{
		ExecuteFn: s.executeDeleteEvent,
	})

	// Init the object
	err := s.init(opts.Log, opts.TraceExporter)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Init the Server object and create a Gin server
func (s *Server) init(log *slog.Logger, traceExporter sdkTrace.SpanExporter) (err error) {
	// Init tracer
	err = s.initTracer(traceExporter)
	if err != nil {
		return err
	}

	s.pubsub.SetLogger(log.With(slog.String("component", "pubsub")))

	s.webAuthn, err = s.initWebAuthn()
	if err != nil {
		return fmt.Errorf("failed to initialize WebAuthn config: %w", err)
	}

	// Init the app server
	err = s.initAppServer(log)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) initTracer(exporter sdkTrace.SpanExporter) error {
	cfg := config.Get()

	// If tracing is disabled, this is a no-op
	if exporter == nil {
		return nil
	}

	resource, err := cfg.GetOtelResource(buildinfo.AppName)
	if err != nil {
		return fmt.Errorf("failed to get OpenTelemetry resource: %w", err)
	}

	s.tracer = sdkTrace.NewTracerProvider(
		sdkTrace.WithResource(resource),
		sdkTrace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(s.tracer)
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}),
	)

	return nil
}

func (s *Server) initAppServer(log *slog.Logger) (err error) {
	cfg := config.Get()

	// Load the TLS configuration
	s.tlsConfig, s.tlsCertWatchFn, err = s.loadTLSConfig(log)
	if err != nil {
		return fmt.Errorf("failed to load TLS configuration: %w", err)
	}

	// Set the baseURL in the webhook
	s.webhook.SetBaseURL(s.getBaseURL())

	// Create the Gin router and add various middlewares
	s.appRouter = gin.New()
	s.appRouter.Use(gin.Recovery())
	s.appRouter.Use(s.MiddlewareMaxBodySize(1 << 20)) // 1MB
	s.appRouter.Use(location.Default())

	// Configure the trusted proxies
	err = s.configureTrustedProxies()
	if err != nil {
		return err
	}

	loggerMw := s.MiddlewareLogger(log)
	addStandardMiddlewares := func(r gin.IRoutes) {
		if s.tracer != nil {
			r.Use(otelgin.Middleware(buildinfo.AppName, otelgin.WithTracerProvider(s.tracer)))
		}

		r.Use(s.MiddlewareRequestId)
		r.Use(s.MiddlewareNoCache)

		if s.metrics != nil {
			r.Use(s.MiddlewareCountMetrics)
		}

		r.Use(loggerMw)
	}

	// Add routes
	// Start with the healthz route
	// This has less middlewares
	healthzGroup := s.appRouter.Group("")
	if s.metrics != nil {
		healthzGroup.Use(s.MiddlewareCountMetrics)
	}
	if !cfg.OmitHealthCheckLogs {
		healthzGroup.Use(loggerMw)
	}
	healthzGroup.GET("/healthz", gin.WrapF(s.RouteHealthzHandler))

	// CSRF protection for browser-facing endpoints.
	// This rejects cross-origin requests on state-changing methods (POST, PUT, DELETE, etc) by checking the Sec-Fetch-Site and Origin headers
	cop := http.NewCrossOriginProtection()
	csrfMw := func(c *gin.Context) {
		cop.
			Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.Next()
			})).
			ServeHTTP(c.Writer, c.Request)

		// If CrossOriginProtection rejected the request, abort the Gin chain
		if c.Writer.Status() == http.StatusForbidden {
			c.Abort()
		}
	}

	// Rate limiters for request creation and authentication endpoints
	requestRateLimiter := MiddlewareRateLimit(requestRateLimit)
	authRateLimiter := MiddlewareRateLimit(authRateLimitRPM)

	// v2 routes (WebAuthn + browser crypto flow)
	v2RouteGroup := s.appRouter.Group("/v2")
	addStandardMiddlewares(v2RouteGroup)

	// Request group is API-to-server (not browser-originated), so no CSRF middleware
	v2RequestGroup := v2RouteGroup.Group("/request")
	v2RequestGroup.Use(requestRateLimiter)
	v2RequestGroup.POST("/:requestKey/encrypt", s.RouteV2RequestCreate("encrypt"))
	v2RequestGroup.POST("/:requestKey/decrypt", s.RouteV2RequestCreate("decrypt"))
	v2RequestGroup.GET("/:requestKey/pubkey", s.RouteV2RequestPubkey)
	v2RequestGroup.GET("/result/:state", s.RouteV2RequestResult)

	// API and auth groups are browser-facing, apply CSRF protection
	v2APIGroup := v2RouteGroup.Group("/api")
	v2APIGroup.Use(csrfMw, s.MiddlewareSession(true))
	v2APIGroup.GET("/list", s.RouteV2APIList)
	v2APIGroup.GET("/request/:state", s.RouteV2APIRequestGet)
	v2APIGroup.POST("/confirm", s.RouteV2APIConfirm)

	v2AuthGroup := v2RouteGroup.Group("/auth")
	v2AuthGroup.Use(csrfMw, authRateLimiter)
	v2AuthGroup.POST("/register/begin", s.RouteV2AuthRegisterBegin)
	v2AuthGroup.POST("/register/finish", s.RouteV2AuthRegisterFinish)
	v2AuthGroup.POST("/login/begin", s.RouteV2AuthLoginBegin)
	v2AuthGroup.POST("/login/finish", s.RouteV2AuthLoginFinish)
	v2AuthGroup.GET("/session", s.MiddlewareSession(false), s.RouteV2AuthSession)
	v2AuthGroup.POST("/finalize-signup", s.MiddlewareSession(false), s.RouteV2AuthFinalizeSignup)
	v2AuthGroup.POST("/allowed-ips", s.MiddlewareSession(true), s.RouteV2AuthAllowedIPs)
	v2AuthGroup.POST("/regenerate-request-key", s.MiddlewareSession(true), s.RouteV2AuthRequestKeyRegenerate)
	v2AuthGroup.POST("/update-display-name", s.MiddlewareSession(true), s.RouteV2AuthUpdateDisplayName)
	v2AuthGroup.POST("/update-wrapped-key", s.MiddlewareSession(true), s.RouteV2AuthUpdateWrappedKey)
	v2AuthGroup.GET("/credentials", s.MiddlewareSession(true), s.RouteV2AuthListCredentials)
	v2AuthGroup.POST("/credentials/add/begin", s.MiddlewareSession(true), s.RouteV2AuthAddCredentialBegin)
	v2AuthGroup.POST("/credentials/add/finish", s.MiddlewareSession(true), s.RouteV2AuthAddCredentialFinish)
	v2AuthGroup.POST("/credentials/rename", s.MiddlewareSession(true), s.RouteV2AuthRenameCredential)
	v2AuthGroup.POST("/credentials/delete", s.MiddlewareSession(true), s.RouteV2AuthDeleteCredential)
	v2AuthGroup.POST("/logout", s.MiddlewareSession(false), s.RouteV2AuthLogout)

	for _, addRoutes := range testRoutes {
		addRoutes(s, s.appRouter)
	}

	// Static files as fallback
	// This doesn't include most middlewares
	s.appRouter.NoRoute(s.serveClient()...)

	return nil
}

func (s *Server) configureTrustedProxies() error {
	trustedProxies := config.Get().TrustedProxies
	if len(trustedProxies) == 0 {
		// Set Gin to not trust any proxy
		trustedProxies = nil
	}

	err := s.appRouter.SetTrustedProxies(trustedProxies)
	if err != nil {
		return fmt.Errorf("error setting trusted proxies in server: %w", err)
	}

	return nil
}

func (s *Server) getBaseURL() string {
	cfg := config.Get()

	// If there's an explicit value in the configuration, use that
	if cfg.BaseUrl != "" {
		return cfg.BaseUrl
	}

	// Build our own
	if s.tlsConfig != nil {
		return "https://localhost:" + strconv.Itoa(cfg.Port)
	} else {
		return "http://localhost:" + strconv.Itoa(cfg.Port)
	}
}

// Run the web server
// Note this function is blocking, and will return only when the servers are shut down via context cancellation.
func (s *Server) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("server is already running")
	}
	defer s.running.Store(false)
	defer s.wg.Wait()

	// Stop the background eventqueue processors
	defer s.requestExpiryQueue.Close()
	defer s.deleteQueue.Close()

	// App server
	s.wg.Add(1)
	err := s.startAppServer(ctx)
	if err != nil {
		return fmt.Errorf("failed to start app server: %w", err)
	}
	defer func() {
		// Handle graceful shutdown
		defer s.wg.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.appSrv.Shutdown(shutdownCtx)
		shutdownCancel()
		if err != nil {
			// Log the error only (could be context canceled)
			logging.LogFromContext(ctx).WarnContext(ctx,
				"App server shutdown error",
				slog.Any("error", err),
			)
		}
	}()
	defer s.pubsub.Shutdown()

	// If we have a tlsCertWatchFn, invoke that
	if s.tlsCertWatchFn != nil {
		err = s.tlsCertWatchFn(ctx)
		if err != nil {
			return fmt.Errorf("failed to watch for TLS certificates: %w", err)
		}
	}

	// Block until the context is canceled
	<-ctx.Done()

	// Servers are stopped with deferred calls
	return nil
}

func (s *Server) startAppServer(ctx context.Context) error {
	cfg := config.Get()
	log := logging.LogFromContext(ctx)

	// Create the HTTP(S) server
	s.appSrv = &http.Server{
		Addr:              net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port)),
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if s.tlsConfig != nil {
		// Using TLS
		s.appSrv.Handler = s.appRouter
		s.appSrv.TLSConfig = s.tlsConfig
	} else {
		// Not using TLS
		// Here we also need to enable HTTP/2 Cleartext
		log.WarnContext(ctx, "Starting app server without TLS - this is not recommended unless Revaulter is exposed through a proxy that offers TLS termination")
		h2s := &http2.Server{}
		s.appSrv.Handler = h2c.NewHandler(s.appRouter, h2s)
	}

	// Create the listener if we don't have one already
	if s.appListener == nil {
		var err error
		s.appListener, err = net.Listen("tcp", s.appSrv.Addr)
		if err != nil {
			return fmt.Errorf("failed to create TCP listener: %w", err)
		}
	}

	// Start the HTTP(S) server in a background goroutine
	log.InfoContext(ctx, "App server started",
		slog.String("bind", cfg.Bind),
		slog.Int("port", cfg.Port),
		slog.Bool("tls", s.tlsConfig != nil),
		slog.String("url", s.getBaseURL()),
	)

	go func() {
		defer s.appListener.Close()

		// Next call blocks until the server is shut down
		var srvErr error
		if s.tlsConfig != nil {
			srvErr = s.appSrv.ServeTLS(s.appListener, "", "")
		} else {
			srvErr = s.appSrv.Serve(s.appListener)
		}
		if srvErr != http.ErrServerClosed {
			slogkit.FatalError(log, "Error starting app server", srvErr)
		}
	}()

	if s.requestStore != nil {
		now := time.Now()
		err := s.requestStore.ExpirePending(ctx, now)
		if err != nil {
			return fmt.Errorf("failed to cleanup expired requests at startup: %w", err)
		}
		_, err = s.requestStore.CleanupOldRecords(ctx, now)
		if err != nil {
			return fmt.Errorf("failed to cleanup old request records at startup: %w", err)
		}

		// Load currently-pending items to enqueue for cleanup
		list, err := s.requestStore.ListPending(ctx)
		if err != nil {
			return fmt.Errorf("failed to initialize request expiry queue: %w", err)
		}
		for _, item := range list {
			err = s.requestExpiryQueue.Enqueue(requestExpiryEvent{
				State:  item.State,
				UserID: item.UserID,
				TTL:    time.Unix(item.Expiry, 0),
			})
			if err != nil {
				return fmt.Errorf("failed to enqueue request expiry for %s: %w", item.State, err)
			}
		}
	}

	if s.authStore != nil {
		err := s.authStore.CleanupExpired(ctx, time.Now())
		if err != nil {
			return fmt.Errorf("failed to cleanup expired auth records at startup: %w", err)
		}
	}
	return nil
}

// Loads the TLS configuration
func (s *Server) loadTLSConfig(log *slog.Logger) (tlsConfig *tls.Config, watchFn tlsCertWatchFn, err error) {
	cfg := config.Get()

	tlsConfig = &tls.Config{
		MinVersion: minTLSVersion,
	}

	// First, check if we have actual keys
	tlsCert := cfg.TLSCertPEM
	tlsKey := cfg.TLSKeyPEM

	// If we don't have actual keys, then we need to load from file and reload when the files change
	if tlsCert == "" && tlsKey == "" {
		// If "tlsPath" is empty, use the folder where the config file is located
		tlsPath := cfg.TLSPath
		if tlsPath == "" {
			file := cfg.GetLoadedConfigPath()
			if file != "" {
				tlsPath = filepath.Dir(file)
			}
		}

		if tlsPath == "" {
			// No config file loaded, so don't attempt to load TLS certs
			return nil, nil, nil
		}

		var provider *tlsCertProvider
		provider, err = newTLSCertProvider(tlsPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load TLS certificates from path '%s': %w", tlsPath, err)
		}

		// If newTLSCertProvider returns nil, there are no TLS certificates, so disable TLS
		if provider == nil {
			return nil, nil, nil
		}

		log.Debug("Loaded TLS certificates from disk", "path", tlsPath)

		tlsConfig.GetCertificate = provider.GetCertificateFn()

		return tlsConfig, provider.Watch, nil
	}

	// Assume the values from the config file are PEM-encoded certs and key
	if tlsCert == "" || tlsKey == "" {
		// If tlsCert and/or tlsKey is empty, do not use TLS
		return nil, nil, nil
	}

	cert, err := tls.X509KeyPair([]byte(tlsCert), []byte(tlsKey))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse TLS certificate or key: %w", err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	log.Debug("Loaded TLS certificates from PEM values")

	return tlsConfig, nil, nil
}
