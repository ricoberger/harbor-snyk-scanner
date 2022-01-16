package metrics

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	reqMetric = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "harbor_snyk_scanner",
		Name:      "chi_requests_total",
		Help:      "Number of HTTP requests processed, partitioned by status code, method and path.",
	}, []string{"response_code", "request_method", "request_path"})

	sumMetric = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Namespace:  "harbor_snyk_scanner",
		Name:       "chi_request_duration_milliseconds",
		Help:       "Latency of HTTP requests processed, partitioned by status code, method and path.",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.95: 0.005, 0.99: 0.001},
	}, []string{"response_code", "request_method", "request_path"})
)

// Metrics is a middleware that handles the Prometheus metrics for the scanner and chi.
func Metrics(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrw := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(wrw, r)

		scanRequestID := chi.URLParam(r, "scan_request_id")
		path := r.URL.Path
		if scanRequestID != "" {
			path = strings.ReplaceAll(path, scanRequestID, "{scan_request_id}")
		}

		reqMetric.WithLabelValues(strconv.Itoa(wrw.Status()), r.Method, path).Inc()
		sumMetric.WithLabelValues(strconv.Itoa(wrw.Status()), r.Method, path).Observe(float64(time.Since(start).Nanoseconds()) / 1000000)
	}

	return http.HandlerFunc(fn)
}
