package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Registrar регистрирует gRPC service implementations на сервере.
type Registrar func(s *grpc.Server)

// Server реализует runtime.Server для gRPC транспорта.
type Server struct {
	name     string
	addr     string
	crtPath  string
	keyPath  string
	register Registrar

	mu  sync.Mutex
	srv *grpc.Server
}

// New создает новый gRPC сервер.
func New(addr string, crtPath string, keyPath string, register Registrar) *Server {
	return &Server{
		name:     "grpc-api:" + addr,
		addr:     addr,
		crtPath:  crtPath,
		keyPath:  keyPath,
		register: register,
	}
}

// Name возвращает имя сервера для runtime orchestration.
func (s *Server) Name() string {
	return s.name
}

// Start поднимает и запускает gRPC server.
func (s *Server) Start(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled: %w", ctx.Err())
	default:
	}

	cert, err := tls.LoadX509KeyPair(s.crtPath, s.keyPath)
	if err != nil {
		return fmt.Errorf("load tls key pair: %w", err)
	}
	creds := credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	})

	listenConfig := net.ListenConfig{}
	lis, err := listenConfig.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	grpcSrv := grpc.NewServer(grpc.Creds(creds))
	if s.register != nil {
		s.register(grpcSrv)
	}

	s.mu.Lock()
	s.srv = grpcSrv
	s.mu.Unlock()

	err = grpcSrv.Serve(lis)
	if errors.Is(err, grpc.ErrServerStopped) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("grpc serve: %w", err)
	}

	return nil
}

// Stop останавливает gRPC server с попыткой graceful shutdown.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	grpcSrv := s.srv
	s.mu.Unlock()

	if grpcSrv == nil {
		return nil
	}

	stopped := make(chan struct{})
	go func() {
		grpcSrv.GracefulStop()
		close(stopped)
	}()

	select {
	case <-ctx.Done():
		grpcSrv.Stop()
		<-stopped

		return fmt.Errorf("grpc server shutdown: %w", ctx.Err())
	case <-stopped:
		return nil
	}
}
