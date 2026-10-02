package handlers

// POST /keys/rotate — forced signing key rotation.
//
// The handler is thin on purpose: the swap is transactional and lives in the rotator,
// where the ordering that keeps the server able to sign is enforced. Reimplementing any
// of it here would be a second copy of the operation that can drift.

import (
	"net/http"

	"oauth-server/internal/domain"
	"oauth-server/internal/httpapi"
)

// RotateKeys forces a signing key rotation.
func (d *Deps) RotateKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpapi.MethodNotAllowed(w, http.MethodPost)
		return
	}
	st := d.state(r)

	if d.KeyRotator == nil {
		d.Logger.Error("rotate_keys: no rotator configured", "correlation_id", st.correlationID)
		httpapi.ServerError(w)
		return
	}

	key, err := d.KeyRotator.ForceRotate(r.Context())
	if err != nil {
		d.Logger.Error("rotate_keys: force rotation", "error", err.Error(), "correlation_id", st.correlationID)
		httpapi.ServerError(w)
		return
	}

	_ = d.AuditLog.Record(r.Context(), st.auditRC(),
		domain.NewAuditEvent(domain.AuditKeyGenerated, domain.AuditOutcomeSuccess, &st.userID), key.KID)

	httpapi.JSON(w, http.StatusOK, map[string]string{"kid": key.KID})
}
