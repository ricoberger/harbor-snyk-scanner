package scanner

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/ricoberger/harbor-snyk-scanner/pkg/log"
	"github.com/ricoberger/harbor-snyk-scanner/pkg/scanner/middleware/httplog"
	"github.com/ricoberger/harbor-snyk-scanner/pkg/scanner/middleware/metrics"
	"github.com/ricoberger/harbor-snyk-scanner/pkg/snyk"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	flag "github.com/spf13/pflag"
	"go.uber.org/zap"
)

var (
	address string
)

// init is used to define all flags, which are needed for the scanner server. We have to define the address, where
// the application server is listen on.
func init() {
	defaultAddress := ":8080"
	if os.Getenv("SCANNER_ADDRESS") != "" {
		defaultAddress = os.Getenv("SCANNER_ADDRESS")
	}

	flag.StringVar(&address, "scanner.address", defaultAddress, "The address, where the scanner server is listen on.")
}

// Server implements the scanner server. The scanner server is used to receive the scanning requests from Harbor.
type Server struct {
	snykClient snyk.Client
	server     *http.Server
}

// Start starts serving the scanner server.
func (s *Server) Start() {
	log.Info(nil, "Scanner server started", zap.String("address", s.server.Addr))

	if err := s.server.ListenAndServe(); err != nil {
		if err != http.ErrServerClosed {
			log.Error(nil, "Scanner server died unexpected", zap.Error(err))
		}
	}
}

// Stop terminates the scanner server gracefully.
func (s *Server) Stop() {
	log.Debug(nil, "Start shutdown of the scanner server")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	err := s.server.Shutdown(ctx)
	if err != nil {
		log.Error(nil, "Graceful shutdown of the scanner server failed", zap.Error(err))
	}
}

// New return a new scanner server.
func New(snykClient snyk.Client) *Server {
	router := chi.NewRouter()

	server := &Server{
		snykClient: snykClient,
		server: &http.Server{
			Addr:    address,
			Handler: router,
		},
	}

	router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, nil)
	})

	router.Route("/api", func(r chi.Router) {
		r.Use(middleware.RequestID)
		r.Use(middleware.Recoverer)
		r.Use(middleware.URLFormat)
		r.Use(metrics.Metrics)
		r.Use(httplog.Logger)

		r.Post("/scan", server.acceptScanRequest)
		r.Get("/scan/{scan_request_id}/report", server.getScanReport)
		r.Get("/metadata", server.getMetadata)
	})

	return server
}
