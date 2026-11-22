package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sendanor/jmap-gateway/internal/gateway"
)

func TestRun(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	config := gateway.Config{
		Listen: "127.0.0.1:0", PublicOrigin: "https://gateway.example", TLSCert: "missing.crt", TLSKey: "missing.key",
		StateDir: state, AccountID: "sender", Token: strings.Repeat("x", 40), IdentityEmail: "sender@example.test",
		IMAP: gateway.Upstream{Address: "localhost:1", Mode: "tls", Username: "test", Password: "test"},
		SMTP: gateway.Upstream{Address: "localhost:1", Mode: "tls", Username: "test", Password: "test"},
	}
	writeConfig := func(name string, config gateway.Config) string {
		t.Helper()
		path := filepath.Join(dir, name)
		data, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	valid := writeConfig("config.json", config)
	config.PublicOrigin = "http://insecure.example"
	invalid := writeConfig("invalid.json", config)
	for _, test := range []struct {
		name    string
		args    []string
		code    int
		message string
	}{
		{"help", []string{"-h"}, 0, "Usage of jmap-gateway"},
		{"unknown flag", []string{"-unknown"}, 2, "flag provided but not defined"},
		{"no config flag", nil, 1, "a configuration path is required"},
		{"config not found", []string{"-config", filepath.Join(dir, "missing")}, 1, "cannot open configuration"},
		{"invalid config", []string{"-config", invalid}, 1, "PublicOrigin must be an HTTPS origin"},
		{"TLS certificate missing", []string{"-config", valid}, 1, "HTTPS listener failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			code := run(context.Background(), test.args, &stderr)
			if code != test.code || !strings.Contains(stderr.String(), test.message) {
				t.Fatalf("exit %d, diagnostic %q", code, stderr.String())
			}
		})
	}
}

type fakeShutdown struct {
	called, closed bool
	err            error
}

func (f *fakeShutdown) Shutdown(ctx context.Context) error {
	f.called = true
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("shutdown requires a deadline")
	}
	return f.err
}

func (f *fakeShutdown) Close() error {
	f.closed = true
	return nil
}

func TestServeShutdown(t *testing.T) {
	for _, graceful := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		server := &fakeShutdown{}
		var stderr bytes.Buffer
		if !graceful {
			server.err = context.DeadlineExceeded
		}
		cancel()
		lifetime := make(chan struct{})
		code := serve(ctx, &stderr, func() error {
			<-lifetime
			return http.ErrServerClosed
		}, server)
		close(lifetime)
		if !server.called || server.closed == graceful || (code == 0) != graceful {
			t.Fatalf("graceful=%t, shutdown=%t, forced close=%t, exit=%d", graceful, server.called, server.closed, code)
		}
		if !graceful && !strings.Contains(stderr.String(), "HTTPS shutdown timed out") {
			t.Fatal("forced shutdown requires a diagnostic")
		}
	}
	listenerEnded := &fakeShutdown{}
	if code := serve(context.Background(), &bytes.Buffer{}, func() error { return http.ErrServerClosed }, listenerEnded); code != 0 || listenerEnded.called {
		t.Fatal("a clean listener exit must succeed")
	}
}
