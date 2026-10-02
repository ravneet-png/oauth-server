package handlers

// GET /health — liveness and readiness.
//
// One endpoint for both, because the operator of this server does not run a separate
// readiness scheduler: a 503 means "do not send me traffic", which is exactly what both
// probes want. The dependency checks are bounded by a timeout so a hung database does
// not hang the probe itself, which would look like a healthy server that is merely slow.

import (
	"context"
	"net/http"
	"time"

	"oauth-server/internal/httpapi"
)

// healthTimeout bounds each dependency probe.
const healthTimeout = 2 * time.Second

// Health handles health checks.
func (d *Deps) Health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpapi.MethodNotAllowed(w, http.MethodGet)
		return
	}

	status := http.StatusOK
	checks := map[string]string{"status": "ok"}

	if d.Config.HealthDependencies && d.Pool != nil {
		ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
		defer cancel()
		if err := d.Pool.GetPool().Ping(ctx); err != nil {
			checks["database"] = "unreachable"
			status = http.StatusServiceUnavailable
		} else {
			checks["database"] = "ok"
		}
	}

	if d.Config.HealthDependencies && d.Cache != nil {
		ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
		defer cancel()
		if err := d.Cache.Ping(ctx); err != nil {
			checks["redis"] = "unreachable"
			status = http.StatusServiceUnavailable
		} else {
			checks["redis"] = "ok"
		}
	}

	if status != http.StatusOK {
		checks["status"] = "degraded"
	}

	httpapi.JSON(w, status, checks)
}
