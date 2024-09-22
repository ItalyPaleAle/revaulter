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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdkTrace "go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/italypaleale/revaulter/pkg/buildinfo"
	"github.com/italypaleale/revaulter/pkg/config"
	"github.com/italypaleale/revaulter/pkg/keyvault"
	"github.com/italypaleale/revaulter/pkg/metrics"
	"github.com/italypaleale/revaulter/pkg/utils"
	"github.com/italypaleale/revaulter/pkg/utils/broker"
	"github.com/italypaleale/revaulter/pkg/utils/webhook"
)

const (
	ndJSONContentType = "application/x-ndjson"
	jsonContentType   = "application/json; charset=utf-8"
)

// Server is the server based on Gin
type Server struct {
	appRouter  *gin.Engine
	httpClient *http.Client
	states     map[string]*requestState
	lock       sync.RWMutex
	webhook    webhook.Webhook
	metrics    *metrics.RevaulterMetrics

	// Subscribers that receive public events
	pubsub *broker.Broker[*requestStatePublic]
	// Subscriptions to watch for state changes
	// Each state can only have one subscription
	// If another call tries to subscribe to the same state, it will evict the first call
	subs map[string]chan *requestState

	// Servers
	appSrv     *http.Server
	metricsSrv *http.Server

	// Method that forces a reload of TLS certificates from disk
	tlsCertWatchFn tlsCertWatchFn

	// TLS configuration for the app server
	tlsConfig *tls.Config

	tracer  *sdkTrace.TracerProvider
	running atomic.Bool
	wg      sync.WaitGroup

	// Listeners for the app and metrics servers
	// These can be used for testing without having to start an actual TCP listener
	appListener     net.Listener
	metricsListener net.Listener

	// Factory for keyvault.Client objects
	// This is defined as a property to allow for mocking
	kvClientFactory keyvault.ClientFactory

	// Optional function to add test routes
	// This is used in testing
	addTestRoutes func(s *Server, r gin.IRouter)
}

// NewServerOpts contains options for the NewServer method
type NewServerOpts struct {
	Log           *slog.Logger
	Webhook       webhook.Webhook
	Metrics       *metrics.RevaulterMetrics
	TraceExporter sdkTrace.SpanExporter

	// Optional function to add test routes
	// This is used in testing
	addTestRoutes func(s *Server, r gin.IRouter)
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
		states:  map[string]*requestState{},
		subs:    map[string]chan *requestState{},
		pubsub:  broker.NewBroker[*requestStatePublic](),
		webhook: opts.Webhook,
		metrics: opts.Metrics,

		httpClient:      httpClient,
		kvClientFactory: keyvault.NewClient,

		addTestRoutes: opts.addTestRoutes,
	}

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
	if !cfg.EnableTracing || exporter == nil {
		return nil
	}

	// Init the trace provider
	s.tracer = sdkTrace.NewTracerProvider(
		sdkTrace.WithResource(cfg.GetOtelResource(buildinfo.AppName)),
		sdkTrace.WithSampler(sdkTrace.ParentBased(sdkTrace.AlwaysSample())),
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
	s.appRouter.Use(s.MiddlewareMaxBodySize)

	// Configure the trusted IP header and proxies
	s.configureTrustedProxies()

	loggerMw := s.MiddlewareLogger(log)
	corsMw := cors.New(s.getCorsConfig())
	addStandardMiddlewares := func(r gin.IRoutes) {
		r.Use(corsMw)
		if s.tracer != nil {
			r.Use(otelgin.Middleware(buildinfo.AppName, otelgin.WithTracerProvider(s.tracer)))
		}
		r.Use(s.MiddlewareRequestId)
		if s.metrics != nil {
			r.Use(s.MiddlewareCountMetrics)
		}
		r.Use(loggerMw)
		r.Use(s.MiddlewareMaxBodySize)
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

	// Logger middleware that removes the auth code from the URL
	codeFilterLogMw := s.MiddlewareLoggerMask(regexp.MustCompile(`(\?|&)(code|state|session_state)=([^&]*)`), "$1$2***")

	// Middleware to allow certain IPs
	allowIpMw, err := s.AllowIpMiddleware()
	if err != nil {
		return err
	}

	// Requests - these share the /request prefix and all use the allow IP middleware
	requestRouteGroup := s.appRouter.Group("/request")
	addStandardMiddlewares(requestRouteGroup)
	requestRouteGroup.Use(allowIpMw, s.RequestKeyMiddleware())
	requestRouteGroup.GET("/result/:state", s.RouteRequestResult)
	requestRouteGroup.POST("/encrypt", s.RouteRequestOperations(OperationEncrypt))
	requestRouteGroup.POST("/decrypt", s.RouteRequestOperations(OperationDecrypt))
	requestRouteGroup.POST("/sign", s.RouteRequestOperations(OperationSign))
	requestRouteGroup.POST("/verify", s.RouteRequestOperations(OperationVerify))
	requestRouteGroup.POST("/wrapkey", s.RouteRequestOperations(OperationWrapKey))
	requestRouteGroup.POST("/unwrapkey", s.RouteRequestOperations(OperationUnwrapKey))

	// API routes - these share the /api prefix
	apiRouteGroup := s.appRouter.Group("/api")
	addStandardMiddlewares(apiRouteGroup)
	apiRouteGroup.GET("/list",
		s.AccessTokenMiddleware(AccessTokenMiddlewareOpts{Required: true}),
		s.RouteApiListGet,
	)
	apiRouteGroup.POST("/confirm",
		s.AccessTokenMiddleware(AccessTokenMiddlewareOpts{Required: true, AllowAccessTokenInHeader: true}),
		s.RouteApiConfirmPost,
	)

	// Auth routes - these share the /auth prefix
	authRouteGroup := s.appRouter.Group("/auth")
	addStandardMiddlewares(authRouteGroup)
	authRouteGroup.GET("/signin", s.RouteAuthSignin)
	authRouteGroup.GET("/confirm", codeFilterLogMw, s.RouteAuthConfirm)

	// Static files as fallback
	// This doesn't include most middlewares
	s.appRouter.NoRoute(s.serveClient())

	return nil
}

func (s *Server) getCorsConfig() cors.Config {
	corsConfig := cors.Config{
		AllowMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodHead,
		},
		AllowHeaders: []string{
			"Authorization",
			"Origin",
			"Content-Length",
			"Content-Type",
		},
		ExposeHeaders: []string{
			"Retry-After",
			"Content-Type",
		},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}

	// Check if we are restricting the origins for CORS
	origins := config.Get().Origins
	switch {
	case len(origins) == 0 || (len(origins) == 1 && origins[0] == ""):
		// Default is baseUrl
		corsConfig.AllowOrigins = []string{s.getBaseURL()}
	case len(origins) == 1 && origins[0] == "*":
		corsConfig.AllowAllOrigins = true
	default:
		corsConfig.AllowAllOrigins = false
		corsConfig.AllowOrigins = origins
	}

	return corsConfig
}

func (s *Server) configureTrustedProxies() {
	// Configure the trusted IP header
	trustedIPHeader := config.Get().TrustedForwardedIPHeader
	if trustedIPHeader != "" {
		// If there's a trusted IP header, the app is behind a proxy, so we trust all addresses for the proxy
		_ = s.appRouter.SetTrustedProxies([]string{"0.0.0.0/0", "::/0"})
		s.appRouter.RemoteIPHeaders = strings.Split(trustedIPHeader, ",")
	} else {
		// Set Gin to not trust any proxy
		_ = s.appRouter.SetTrustedProxies(nil)
	}
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

	cfg := config.Get()

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
			utils.LogFromContext(ctx).WarnContext(ctx,
				"App server shutdown error",
				slog.Any("error", err),
			)
		}
	}()
	defer s.pubsub.Shutdown()

	// Metrics server
	if cfg.MetricsServerEnabled && s.metrics != nil {
		s.wg.Add(1)
		err = s.startMetricsServer(ctx)
		if err != nil {
			return fmt.Errorf("failed to start metrics server: %w", err)
		}
		defer func() {
			// Handle graceful shutdown
			defer s.wg.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			err := s.metricsSrv.Shutdown(shutdownCtx)
			shutdownCancel()
			if err != nil {
				// Log the error only (could be context canceled)
				utils.LogFromContext(ctx).WarnContext(ctx,
					"Metrics server shutdown error",
					slog.Any("error", err),
				)
			}
		}()
	}

	// Tracer shutdown
	if s.tracer != nil {
		defer func() {
			// Use a background context here as the parent context is done
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
			err = s.tracer.Shutdown(shutdownCtx)
			shutdownCancel()
			if err != nil {
				// Log the error only (could be context canceled)
				utils.LogFromContext(ctx).WarnContext(ctx,
					"Trace provider shutdown error",
					slog.Any("error", err),
				)
			}
		}()
	}

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
	log := utils.LogFromContext(ctx)

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
			utils.FatalError(log, "Error starting app server", srvErr)
		}
	}()

	return nil
}

func (s *Server) startMetricsServer(ctx context.Context) error {
	cfg := config.Get()
	log := utils.LogFromContext(ctx)

	// Handler
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.RouteHealthzHandler)
	mux.Handle("/metrics", s.metrics.HTTPHandler())

	// Create the HTTP server
	s.metricsSrv = &http.Server{
		Addr:              net.JoinHostPort(cfg.MetricsServerBind, strconv.Itoa(cfg.MetricsServerPort)),
		Handler:           mux,
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Create the listener if we don't have one already
	if s.metricsListener == nil {
		var err error
		s.metricsListener, err = net.Listen("tcp", s.metricsSrv.Addr)
		if err != nil {
			return fmt.Errorf("failed to create TCP listener: %w", err)
		}
	}

	// Start the HTTPS server in a background goroutine
	log.InfoContext(ctx, "Metrics server started",
		slog.String("bind", cfg.MetricsServerBind),
		slog.Int("port", cfg.MetricsServerPort),
	)
	go func() {
		defer s.metricsListener.Close()

		// Next call blocks until the server is shut down
		srvErr := s.metricsSrv.Serve(s.metricsListener)
		if srvErr != http.ErrServerClosed {
			utils.FatalError(log, "Error starting metrics server", srvErr)
		}
	}()

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

type operationResponse struct {
	State   string `json:"state"`
	Pending bool   `json:"pending,omitempty"`
	Done    bool   `json:"done,omitempty"`
	Failed  bool   `json:"failed,omitempty"`

	keyvault.KeyVaultResponse `json:"response,omitempty"`
}
