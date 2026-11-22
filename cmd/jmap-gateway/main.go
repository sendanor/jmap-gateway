package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sendanor/jmap-gateway/internal/gateway"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	status := run(ctx, os.Args[1:], os.Stderr)
	stop()
	os.Exit(status)
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("jmap-gateway", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "path to private JSON configuration")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *path == "" {
		fmt.Fprintln(stderr, "a configuration path is required")
		return 1
	}
	config, err := gateway.LoadConfig(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	handler, err := gateway.New(config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer handler.Close()

	server := &http.Server{
		Addr: config.Listen, Handler: handler, TLSConfig: gateway.ServerTLS(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 75 * time.Second, IdleTimeout: 60 * time.Second,
	}
	server.RegisterOnShutdown(handler.StopEvents)
	return serve(ctx, stderr, func() error {
		return server.ListenAndServeTLS(config.TLSCert, config.TLSKey)
	}, server)
}

type shutdownServer interface {
	Shutdown(context.Context) error
	Close() error
}

func serve(ctx context.Context, stderr io.Writer, listen func() error, server shutdownServer) int {
	done := make(chan error, 1)
	go func() { done <- listen() }()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(stderr, "HTTPS listener failed")
			return 1
		}
	case <-ctx.Done():
		timeout, cancel := context.WithTimeout(context.Background(), 75*time.Second)
		defer cancel()
		if err := server.Shutdown(timeout); err != nil {
			fmt.Fprintln(stderr, "HTTPS shutdown timed out")
			_ = server.Close()
			return 1
		}
	}
	return 0
}
