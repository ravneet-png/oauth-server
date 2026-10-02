package handlers

// DELETE /users/{id} — GDPR erasure.
//
// Erasure is not a delete of one row. The user is referenced by sessions, client
// sessions, access and refresh tokens, consents, MFA seeds, verification tokens and the
// audit log. Leaving any of those behind leaves personal data behind, and leaving a live
// session behind means the subject can still be acted on after asking to be forgotten.
//
// The back-channel logout notifications are built before anything is deleted, from the
// client sessions that still exist, and delivered afterwards. Building them first is what
// lets a relying party be told to end the session; delivering after is what keeps a slow
// RP from holding the erasure transaction open.

import (
	"net/http"
	"time"

	"oauth-server/internal/domain"
	"oauth-server/internal/httpapi"
	"oauth-server/internal/oautherr"
	"oauth-server/internal/storage"
	"oauth-server/internal/tokens"
)

// EraseUser handles account erasure.
func (d *Deps) EraseUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		httpapi.MethodNotAllowed(w, http.MethodDelete)
		return
	}
	st := d.state(r)

	userID := r.PathValue("id")
	if userID == "" {
		httpapi.OAuthError(w, oautherr.New(domain.NewInvalidRequest("user id is required")))
		return
	}

	if _, err := d.Users.GetByID(r.Context(), userID); err != nil {
		httpapi.JSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}

	// 1. Collect everything the notifications need, while the rows still exist.
	clientSessions, err := d.ClientSess.GetByUserID(r.Context(), userID)
	if err != nil {
		d.Logger.Error("erase: load client sessions", "error", err.Error(), "correlation_id", st.correlationID)
		httpapi.ServerError(w)
		return
	}
	type logoutDelivery struct {
		endpoint string
		token    string
	}
	var deliveries []logoutDelivery
	for _, cs := range clientSessions {
		client, err := d.Clients.GetByID(r.Context(), cs.ClientID)
		if err != nil || client.BackchannelLogoutURI == nil || *client.BackchannelLogoutURI == "" {
			continue
		}
		logoutToken, err := d.LogoutBldr.Build(r.Context(), tokens.LogoutTokenParams{
			UserID:   userID,
			ClientID: cs.ClientID,
			SID:      cs.SID,
			TTL:      2 * time.Minute,
		})
		if err != nil {
			// A client that cannot be notified is not a reason to refuse the erasure.
			d.Logger.Warn("erase: build logout token", "error", err.Error(), "client_id", cs.ClientID)
			continue
		}
		deliveries = append(deliveries, logoutDelivery{endpoint: *client.BackchannelLogoutURI, token: logoutToken})
	}
	sessionIDs := make([]string, 0, len(clientSessions))
	for _, cs := range clientSessions {
		if cs.SessionID != "" {
			sessionIDs = append(sessionIDs, cs.SessionID)
		}
	}

	// 2. Revoke access tokens before detaching them, so a token that is already in a
	// relying party's hands is refused on the next introspection or userinfo call.
	if active, err := d.AccessToks.GetActiveByUserID(r.Context(), userID); err == nil && len(active) > 0 {
		entries := make([]storage.RevocationEntry, 0, len(active))
		for _, t := range active {
			entries = append(entries, storage.RevocationEntry{JTI: t.JTI, ExpiresAt: t.ExpiresAt})
		}
		if err := d.Revoked.AddBatch(r.Context(), entries); err != nil {
			d.Logger.Error("erase: revoke access tokens", "error", err.Error(), "correlation_id", st.correlationID)
			httpapi.ServerError(w)
			return
		}
	}

	if _, err := d.RefreshToks.RevokeAllForUser(r.Context(), userID, domain.RevocationReasonGDPR); err != nil {
		d.Logger.Error("erase: revoke refresh tokens", "error", err.Error(), "correlation_id", st.correlationID)
		httpapi.ServerError(w)
		return
	}

	// 3. Detach and delete the user's own records. Each step is idempotent, so a crash
	// partway through leaves a partially erased account that a re-run completes rather
	// than a corrupt one.
	if _, err := d.AccessToks.DetachUser(r.Context(), userID); err != nil {
		d.Logger.Error("erase: detach access tokens", "error", err.Error(), "correlation_id", st.correlationID)
		httpapi.ServerError(w)
		return
	}
	if _, err := d.Sessions.DeleteAllForUser(r.Context(), userID); err != nil {
		d.Logger.Error("erase: delete sessions", "error", err.Error(), "correlation_id", st.correlationID)
		httpapi.ServerError(w)
		return
	}
	if _, err := d.ClientSess.DeleteByUserID(r.Context(), userID); err != nil {
		d.Logger.Error("erase: delete client sessions", "error", err.Error(), "correlation_id", st.correlationID)
		httpapi.ServerError(w)
		return
	}
	if err := d.Consent.DeleteAllForUser(r.Context(), userID); err != nil {
		d.Logger.Error("erase: delete consents", "error", err.Error(), "correlation_id", st.correlationID)
		httpapi.ServerError(w)
		return
	}
	if _, err := d.MFA.DeleteForUser(r.Context(), userID); err != nil {
		d.Logger.Error("erase: delete mfa", "error", err.Error(), "correlation_id", st.correlationID)
		httpapi.ServerError(w)
		return
	}
	if _, err := d.EmailVerif.DeleteForUser(r.Context(), userID); err != nil {
		d.Logger.Error("erase: delete verifications", "error", err.Error(), "correlation_id", st.correlationID)
		httpapi.ServerError(w)
		return
	}

	// 4. Pseudonymise the audit trail before deleting the account row, because after the
	// delete there is no user row to correlate the pseudonym against — which is the
	// point: the trail stays useful for the operator and stops naming the subject.
	for _, sid := range sessionIDs {
		if _, err := d.Audit.AnonymizeSession(r.Context(), sid); err != nil {
			d.Logger.Warn("erase: anonymise session", "error", err.Error(), "session_id", sid)
		}
	}
	if _, err := d.Audit.AnonymizeUser(r.Context(), userID); err != nil {
		d.Logger.Error("erase: anonymise audit", "error", err.Error(), "correlation_id", st.correlationID)
		httpapi.ServerError(w)
		return
	}

	if err := d.Users.Delete(r.Context(), userID); err != nil {
		d.Logger.Error("erase: delete user", "error", err.Error(), "correlation_id", st.correlationID)
		httpapi.ServerError(w)
		return
	}

	// 5. Deliver the notifications that were built while the rows existed. Failures are
	// logged and dropped: the data is already gone, and returning an error would tell
	// the administrator the erasure failed when it did not.
	for _, delivery := range deliveries {
		if err := d.Backchannel.Deliver(r.Context(), delivery.endpoint, delivery.token); err != nil {
			d.Logger.Warn("erase: deliver logout token", "error", err.Error())
			_ = d.AuditLog.Record(r.Context(), st.auditRC(),
				domain.NewAuditEvent(domain.AuditBackchannelLogoutFail, domain.AuditOutcomeFailure, nil), userID)
		}
	}

	if err := d.AuditLog.UserErased(r.Context(), st.auditRC(), st.userID, userID); err != nil {
		d.Logger.Error("erase: audit", "error", err.Error(), "correlation_id", st.correlationID)
	}

	w.WriteHeader(http.StatusNoContent)
}
