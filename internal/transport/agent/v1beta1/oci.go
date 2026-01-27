package agenttransportv1beta1

import (
	"context"
	"net/http"

	"github.com/flightctl/flightctl/internal/api_server/middleware"
	"github.com/flightctl/flightctl/internal/consts"
	"github.com/flightctl/flightctl/internal/service"
	"github.com/flightctl/flightctl/internal/transport"
	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"
)

// OCITransportHandler handles OCI Distribution API requests from agents.
type OCITransportHandler struct {
	serviceHandler service.Service
	log            logrus.FieldLogger
}

// NewOCITransportHandler creates a new OCI transport handler.
func NewOCITransportHandler(serviceHandler service.Service, log logrus.FieldLogger) *OCITransportHandler {
	return &OCITransportHandler{serviceHandler: serviceHandler, log: log}
}

// RegisterRoutes registers OCI Distribution API routes on the router.
// These routes are mounted at /v2/ to follow OCI Distribution spec.
func (h *OCITransportHandler) RegisterRoutes(r chi.Router) {
	// OCI Distribution API version check
	r.Get("/", h.VersionCheck)

	// Catalog manifest endpoint
	// GET /v2/catalogs/{org}/{source}/{app}/manifests/{reference}
	r.Get("/catalogs/{org}/{source}/{app}/manifests/{reference}", h.GetManifest)
}

// VersionCheck handles GET /v2/ - OCI Distribution spec version check.
// Returns 200 OK if the registry supports the OCI Distribution spec.
func (h *OCITransportHandler) VersionCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}

// GetManifest handles GET /v2/catalogs/{org}/{source}/{app}/manifests/{reference}
// Returns an OCI manifest for the specified catalog item.
func (h *OCITransportHandler) GetManifest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract route parameters
	// Note: the {org} in the URL is informational - actual org comes from auth context
	source := chi.URLParam(r, "source")
	app := chi.URLParam(r, "app")
	reference := chi.URLParam(r, "reference")

	// Validate the agent is authenticated
	val := ctx.Value(consts.IdentityCtxKey)
	if val == nil {
		h.log.Error("agent identity is missing from context")
		h.writeOCIError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	_, ok := val.(*middleware.AgentIdentity)
	if !ok {
		h.log.Error("invalid agent identity type in context")
		h.writeOCIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
		return
	}

	// Get org from context (set by auth middleware)
	orgId := transport.OrgIDFromContext(ctx)

	// Get the manifest from the service
	manifest, mediaType, status := h.serviceHandler.GetCatalogManifest(ctx, orgId, source, app, reference)
	if status.Code != http.StatusOK {
		switch status.Code {
		case http.StatusNotFound:
			h.writeOCIError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", status.Message)
		case http.StatusBadRequest:
			h.writeOCIError(w, http.StatusBadRequest, "MANIFEST_INVALID", status.Message)
		default:
			h.writeOCIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", status.Message)
		}
		return
	}

	// Set OCI-compliant headers
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")

	// Compute and set the digest header if not already known
	// For now, we'll skip this - in production you'd compute sha256 of manifest
	// w.Header().Set("Docker-Content-Digest", "sha256:...")

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(manifest)
}

// writeOCIError writes an OCI Distribution spec-compliant error response.
func (h *OCITransportHandler) writeOCIError(w http.ResponseWriter, statusCode int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(statusCode)

	// OCI error format
	errorJSON := `{"errors":[{"code":"` + code + `","message":"` + message + `"}]}`
	_, _ = w.Write([]byte(errorJSON))
}

// isAgentAuthenticated checks if the request has valid agent authentication.
// This is used for authorization checks beyond what the middleware provides.
func (h *OCITransportHandler) isAgentAuthenticated(ctx context.Context) bool {
	val := ctx.Value(consts.IdentityCtxKey)
	if val == nil {
		return false
	}
	_, ok := val.(*middleware.AgentIdentity)
	return ok
}
