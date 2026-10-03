// Run database migrations. Supports up, down, force, status and create. Reads
// the database URL from config and environment. Used by the Makefile migrate
// targets.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/subosito/gotenv"

	"oauth-server/internal/storage"
)

//nolint:gosec // G101: local development database URL default
const defaultDevDBURL = "postgres://oauth:oauth@localhost:5432/oauth?sslmode=disable"

func main() {
	var (
		direction = flag.String("direction", "up", "migration direction: up, down, status, force, create")
		steps     = flag.Int("steps", 1, "number of migrations to roll back for down")
		version   = flag.Int("version", 0, "target schema version for force")
		name      = flag.String("name", "", "migration name for create")
		dbURL     = flag.String("db", "", "database URL (defaults to OAUTH_DATABASE_URL or local dev DB)")
	)
	flag.Parse()

	if err := gotenv.Load(".env"); err != nil && !os.IsNotExist(err) {
		slog.Warn("could not read .env", "error", err)
	}

	resolvedURL := resolveDBURL(*dbURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch strings.ToLower(strings.TrimSpace(*direction)) {
	case "up":
		if err := storage.RunMigrations(ctx, resolvedURL); err != nil {
			slog.Error("migrate up failed", "error", err)
			os.Exit(1)
		}
		slog.Info("migrations applied")

	case "down":
		if err := storage.MigrateDown(ctx, resolvedURL, *steps); err != nil {
			slog.Error("migrate down failed", "error", err)
			os.Exit(1)
		}
		slog.Info("migrations rolled back", "steps", *steps)

	case "status":
		ver, dirty, err := storage.MigrateStatus(ctx, resolvedURL)
		if err != nil {
			slog.Error("migrate status failed", "error", err)
			os.Exit(1)
		}
		fmt.Printf("version=%d dirty=%t\n", ver, dirty)

	case "force":
		if err := storage.MigrateForce(ctx, resolvedURL, *version); err != nil {
			slog.Error("migrate force failed", "error", err)
			os.Exit(1)
		}
		slog.Info("migration version forced", "version", *version)

	case "create":
		if err := createMigrationFiles(*name); err != nil {
			slog.Error("migrate create failed", "error", err)
			os.Exit(1)
		}

	default:
		slog.Error("unknown migration direction", "direction", *direction)
		os.Exit(1)
	}
}

func resolveDBURL(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv("OAUTH_DATABASE_URL"); v != "" {
		return v
	}
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	return defaultDevDBURL
}

func createMigrationFiles(rawName string) error {
	clean := strings.TrimSpace(rawName)
	if clean == "" {
		return errors.New("migration name is required (-name)")
	}
	clean = strings.ReplaceAll(clean, " ", "_")
	stamp := time.Now().UTC().Format("20060102150405")
	upPath := filepath.Join("migrations", fmt.Sprintf("%s_%s.up.sql", stamp, clean))
	downPath := filepath.Join("migrations", fmt.Sprintf("%s_%s.down.sql", stamp, clean))

	if err := os.WriteFile(upPath, []byte("-- Up migration\nSELECT 1;\n"), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", upPath, err)
	}
	if err := os.WriteFile(downPath, []byte("-- Down migration\nSELECT 1;\n"), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", downPath, err)
	}
	slog.Info("created migration files", "up", upPath, "down", downPath)
	return nil
}
