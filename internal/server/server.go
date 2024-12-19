package server

import (
	"context"
	"net/http"
	"time"
)

const (
	defaultAddr            = "0.0.0.0:8080"
	defaultShutdownTimeout = 3 * time.Second
)

type Server struct {
	server          *http.Server
	notify          chan error
	shutDownTimeout time.Duration
}

func New(handler http.Handler) *Server {
	httpServer := &http.Server{
		Handler: handler,
		Addr:    defaultAddr,
	}

	notifyChan := make(chan error, 1)

	s := Server{
		server:          httpServer,
		notify:          notifyChan,
		shutDownTimeout: defaultShutdownTimeout,
	}

	s.start()

	return &s
}

func (s *Server) start() {
	go func() {
		s.notify <- s.server.ListenAndServe()
		close(s.notify)
	}()
}

func (s *Server) Notify() chan error {
	return s.notify
}

func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.shutDownTimeout)
	defer cancel()

	return s.server.Shutdown(ctx)
}
