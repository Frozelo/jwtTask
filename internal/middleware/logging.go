package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

type LoggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func LoggingMiddleware(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			next.ServeHTTP(w, r)

			logger.Info("Incoming request",
				"method", r.Method,
				"path", r.URL.Path,
				"duration", time.Since(start).String(),
				"client_ip", r.RemoteAddr,
			)
		})
	}
}
