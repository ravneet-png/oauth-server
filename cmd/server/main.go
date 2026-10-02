// Wiring and process lifecycle only. Loads config, constructs the app graph,
// starts the HTTP server and background workers, and handles graceful shutdown.
// No business logic.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/subosito/gotenv"

	"oauth-server/internal/app"
	"oauth-server/internal/config"
	"oauth-server/internal/storage"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// .env is optional and is loaded before anything reads the environment. A missing
	// file is not an error: the deployment may supply variables directly, and treating
	// its absence as fatal would make the binary unusable in every environment that
	// does not use a file.
	if err := gotenv.Load(".env"); err != nil && !os.IsNotExist(err) {
		slog.Warn("could not read .env", "error", err)
	}

	cfg, secrets, err := config.Load(config.LoaderOptions{
		EnvPrefix:   "OAUTH_",
		Environment: ensureDevelopmentSecrets(os.Environ()),
	})
	if err != nil {
		slog.Error("configuration rejected", "error", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.Logging)
	slog.SetDefault(logger)

	if err := storage.RunMigrations(ctx, cfg.Database.URL); err != nil {
		logger.Error("database migration failed", "error", err)
		os.Exit(1)
	}

	application, err := app.New(ctx, app.Options{
		Config:  cfg,
		Secrets: secrets,
		Logger:  logger,
	})
	if err != nil {
		logger.Error("application construction failed", "error", err)
		os.Exit(1)
	}
	defer application.Close()

	application.Rotator.Start(ctx)
	application.Reaper.Start(ctx)

	srv := &http.Server{
		Addr:    net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port)),
		Handler: application.Router,
		// ReadHeaderTimeout is the only timeout that can be short without breaking
		// large uploads or slow clients: it bounds how long a peer may take to send
		// its headers, which is the slowloris window. The others are generous.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	go func() {
		<-ctx.Done()
		logger.Info("shutting down HTTP server")
		// 30s is the drain budget: in-flight requests are allowed to finish, and a
		// request that outlives it is cut rather than holding shutdown open. It must
		// exceed the server WriteTimeout (60s) only if slow responses are expected;
		// here it is deliberately shorter than ReadTimeout so a stuck client cannot
		// prevent a clean exit, and matches the deployment's orchestrator grace period.
		// Background, not the signal-detached request context: Shutdown must still
		// receive a deadline even if the context that triggered the signal was
		// already cancelled.
		// A fresh context is required here, not one inherited from the signal
		// handler: that one is already cancelled, and Shutdown needs a live
		// deadline to drain against.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil { //nolint:contextcheck // deliberate fresh context
			logger.Error("HTTP shutdown", "error", err)
		}
	}()

	logger.Info("server starting", "addr", srv.Addr, "issuer", cfg.Server.Issuer, "env", cfg.Env)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	// Stop the rotator before the pool closes, with a fresh context because the
	// signal context is already cancelled and a cancelled context would make Stop
	// return immediately without joining its goroutines.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	if err := application.Rotator.Stop(stopCtx); err != nil {
		logger.Error("rotator stop", "error", err)
	}
	if err := application.Reaper.Stop(stopCtx); err != nil {
		logger.Error("reaper stop", "error", err)
	}
	logger.Info("shutdown complete")
}

// ensureDevelopmentSecrets fills in ephemeral key material when running in development
// without a .env, so a fresh checkout boots.
//
// The keys are generated per process and are not persisted; every restart makes prior
// encrypted rows unreadable, which is the intended behaviour for a development-only
// convenience and the reason this branch is gated on the environment name.
//
// The check reads OAUTH_ENV directly because config.Load validates the secrets, so this
// must run before it. Only variables that are absent are filled; anything the operator
// supplied is left untouched.
func ensureDevelopmentSecrets(env []string) []string {
	switch strings.ToLower(envValue(env, "OAUTH_ENV")) {
	case "dev", "development", "local", "test", "testing":
	default:
		return env
	}

	for _, name := range []string{"OAUTH_KEY_ENCRYPTION_KEY", "OAUTH_AUDIT_PEPPER"} {
		if envValue(env, name) != "" {
			continue
		}
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			slog.Error("generate development secret", "name", name, "error", err)
			os.Exit(1)
		}
		env = append(env, name+"="+hex.EncodeToString(buf))
		slog.Warn("using a generated development secret; encrypted data will not survive a restart", "name", name)
	}
	return env
}

// envValue returns the value of name in an os.Environ-shaped slice.
func envValue(env []string, name string) string {
	prefix := name + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return kv[len(prefix):]
		}
	}
	return ""
}

// newLogger builds the process logger from the logging configuration.
func newLogger(cfg config.LoggingConfig) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.ToLower(cfg.Format) == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}
