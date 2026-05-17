// Package handlers — MCP Auth Sessions tab API.
//
// Surfaces the per-user OAuth token rows and pending flow rows visible to the
// caller's identity. Mode-strict: the handler derives AuthMode at request time
// via ctx.AuthMode() and only returns rows whose identity column matches.
// Orphaned tokens are included in the listing so the UI can surface "needs
// re-auth"; they never satisfy a runtime token lookup (filtered at the
// resolver layer).
package handlers

import (
	"github.com/fasthttp/router"
	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
)

// MCPSessionsHandler serves the sessions tab API.
type MCPSessionsHandler struct {
	store *lib.Config
}

// NewMCPSessionsHandler creates the handler.
func NewMCPSessionsHandler(store *lib.Config) *MCPSessionsHandler {
	return &MCPSessionsHandler{store: store}
}

// RegisterRoutes registers the sessions tab routes.
func (h *MCPSessionsHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	r.GET("/api/mcp/sessions", lib.ChainMiddlewares(h.list, middlewares...))
	r.POST("/api/mcp/sessions/{id}/reauth", lib.ChainMiddlewares(h.reauth, middlewares...))
	r.DELETE("/api/mcp/sessions/{id}", lib.ChainMiddlewares(h.revoke, middlewares...))
	r.GET("/api/oauth/per-user/flows/{id}", lib.ChainMiddlewares(h.flowDetail, middlewares...))
	r.GET("/api/oauth/per-user/flows/{id}/start", lib.ChainMiddlewares(h.flowStart, middlewares...))
}

// mcpSessionRow is the wire shape for both authenticated tokens and pending flows.
type mcpSessionRow struct {
	ID            string  `json:"id"`
	Kind          string  `json:"kind"` // "token" | "flow"
	AuthMode      string  `json:"auth_mode"`
	UserID        *string `json:"user_id,omitempty"`
	VirtualKeyID  *string `json:"virtual_key_id,omitempty"`
	MCPClientID   string  `json:"mcp_client_id"`
	Status        string  `json:"status"`               // 'active' | 'orphaned' | 'pending'
	ExpiresAt     *string `json:"expires_at,omitempty"` // RFC3339; nil for non-expiring tokens
	CreatedAt     string  `json:"created_at"`
	OauthConfigID string  `json:"oauth_config_id,omitempty"`
}

type mcpSessionsListResponse struct {
	Sessions []mcpSessionRow `json:"sessions"`
}

// list returns sessions visible to the caller. Each row's identity column
// matches the caller's derived AuthMode + identity.
func (h *MCPSessionsHandler) list(ctx *fasthttp.RequestCtx) {
	bfCtx, cancel := lib.ConvertToBifrostContext(ctx, h.store)
	defer cancel()

	mode, identity := callerModeAndIdentity(bfCtx)
	if mode == schemas.AuthModeNone && identity == "" {
		SendJSON(ctx, mcpSessionsListResponse{Sessions: []mcpSessionRow{}})
		return
	}

	tokens, err := h.store.ConfigStore.ListOauthUserTokensByMode(ctx, mode, identity, true /*includeOrphaned*/)
	if err != nil {
		logger.Error("[mcp/sessions] list tokens failed: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to list MCP sessions")
		return
	}
	flows, err := h.store.ConfigStore.ListOauthUserSessionsByMode(ctx, mode, identity)
	if err != nil {
		logger.Error("[mcp/sessions] list flows failed: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to list MCP sessions")
		return
	}

	rows := make([]mcpSessionRow, 0, len(tokens)+len(flows))
	for _, t := range tokens {
		rows = append(rows, tokenRow(t))
	}
	for _, f := range flows {
		rows = append(rows, flowRow(f))
	}
	SendJSON(ctx, mcpSessionsListResponse{Sessions: rows})
}

// reauth starts a fresh OAuth flow for the MCP client backing the given token
// row. Returns the authorize URL the user must visit.
func (h *MCPSessionsHandler) reauth(ctx *fasthttp.RequestCtx) {
	rowID, ok := ctx.UserValue("id").(string)
	if !ok || rowID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid session id")
		return
	}
	bfCtx, cancel := lib.ConvertToBifrostContext(ctx, h.store)
	defer cancel()

	mode, identity := callerModeAndIdentity(bfCtx)
	if identity == "" {
		SendError(ctx, fasthttp.StatusUnauthorized, "No identity to scope this session to")
		return
	}

	tok, err := h.loadAuthorizedToken(ctx, rowID, mode, identity)
	if err != nil {
		// loadAuthorizedToken already wrote the error response.
		_ = err
		return
	}

	provider := h.store.OAuthProvider
	if provider == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "OAuth provider not configured")
		return
	}
	redirectURI := lib.BuildBaseURL(ctx, h.store.GetMCPExternalClientURL()) + "/api/oauth/callback"
	flow, sessionID, err := provider.InitiateUserOAuthFlow(bfCtx, tok.OauthConfigID, tok.MCPClientID, redirectURI, mode)
	if err != nil {
		logger.Error("[mcp/sessions] reauth flow init failed: token=%s err=%v", rowID, err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to initiate reauthentication")
		return
	}
	logger.Info("[mcp/sessions] reauth initiated: token=%s mcp_client=%s mode=%s flow=%s", rowID, tok.MCPClientID, mode, sessionID)
	SendJSON(ctx, map[string]any{
		"authorize_url": flow.AuthorizeURL,
		"session_id":    sessionID,
	})
}

// revoke best-effort revokes the upstream token and hard-deletes the row.
// Permission is the same mode-strict identity match as list/reauth.
func (h *MCPSessionsHandler) revoke(ctx *fasthttp.RequestCtx) {
	rowID, ok := ctx.UserValue("id").(string)
	if !ok || rowID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid session id")
		return
	}
	bfCtx, cancel := lib.ConvertToBifrostContext(ctx, h.store)
	defer cancel()

	mode, identity := callerModeAndIdentity(bfCtx)
	if identity == "" {
		SendError(ctx, fasthttp.StatusUnauthorized, "No identity to scope this session to")
		return
	}

	tok, err := h.loadAuthorizedToken(ctx, rowID, mode, identity)
	if err != nil {
		_ = err
		return
	}

	// Best-effort upstream revoke via the session token (which keys the
	// RefreshUserAccessToken / RevokeUserToken path).
	if tok.SessionToken != "" {
		if revokeErr := h.store.OAuthProvider.RevokeUserToken(ctx, tok.SessionToken); revokeErr != nil {
			logger.Warn("[mcp/sessions] upstream revoke failed (continuing with row delete): token=%s err=%v", rowID, revokeErr)
		}
	}

	if err := h.store.ConfigStore.DeleteOauthUserToken(ctx, tok.ID); err != nil {
		logger.Error("[mcp/sessions] delete row failed: token=%s err=%v", rowID, err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to delete MCP session")
		return
	}
	logger.Info("[mcp/sessions] revoked: token=%s mcp_client=%s mode=%s", rowID, tok.MCPClientID, mode)
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}

// mcpFlowDetailResponse is the wire shape for GET /api/oauth/per-user/flows/{id}.
type mcpFlowDetailResponse struct {
	ID            string  `json:"id"`
	FlowMode      string  `json:"flow_mode"`
	Status        string  `json:"status"`
	MCPClientID   string  `json:"mcp_client_id"`
	OauthConfigID string  `json:"oauth_config_id"`
	UserID        *string `json:"user_id,omitempty"`
	VirtualKeyID  *string `json:"virtual_key_id,omitempty"`
	ExpiresAt     string  `json:"expires_at"`
	CreatedAt     string  `json:"created_at"`
}

// flowDetail returns the pending flow row's metadata so the frontend sessions
// auth page can render a "you're about to authenticate X" view.
//
// Permission model: deferred-fill flows (flow_mode='user' with user_id=nil)
// are visible to any user-mode caller — the first SCIM-authenticated user to
// open the URL will become the row's user_id at completion time. For all
// other modes the caller's identity must match the row's identity column.
func (h *MCPSessionsHandler) flowDetail(ctx *fasthttp.RequestCtx) {
	flowID, ok := ctx.UserValue("id").(string)
	if !ok || flowID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid flow id")
		return
	}
	bfCtx, cancel := lib.ConvertToBifrostContext(ctx, h.store)
	defer cancel()

	flow, err := h.loadAuthorizedFlow(ctx, bfCtx, flowID)
	if err != nil {
		_ = err
		return
	}
	SendJSON(ctx, mcpFlowDetailResponse{
		ID:            flow.ID,
		FlowMode:      flow.FlowMode,
		Status:        flow.Status,
		MCPClientID:   flow.MCPClientID,
		OauthConfigID: flow.OauthConfigID,
		UserID:        flow.UserID,
		VirtualKeyID:  flow.VirtualKeyID,
		ExpiresAt:     flow.ExpiresAt.UTC().Format(rfc3339Nano),
		CreatedAt:     flow.CreatedAt.UTC().Format(rfc3339Nano),
	})
}

// flowStart reconstructs the upstream provider authorize URL for a pending
// flow and returns it. The frontend redirects the browser to that URL; the
// user completes upstream auth; upstream redirects back to /api/oauth/callback
// which calls CompleteUserOAuthFlow.
func (h *MCPSessionsHandler) flowStart(ctx *fasthttp.RequestCtx) {
	flowID, ok := ctx.UserValue("id").(string)
	if !ok || flowID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid flow id")
		return
	}
	bfCtx, cancel := lib.ConvertToBifrostContext(ctx, h.store)
	defer cancel()

	if _, err := h.loadAuthorizedFlow(ctx, bfCtx, flowID); err != nil {
		_ = err
		return
	}
	if h.store.OAuthProvider == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "OAuth provider not configured")
		return
	}
	upstreamURL, err := h.store.OAuthProvider.BuildUpstreamAuthorizeURL(ctx, flowID)
	if err != nil {
		logger.Error("[mcp/sessions] flow start failed: flow=%s err=%v", flowID, err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to build upstream authorize URL")
		return
	}
	SendJSON(ctx, map[string]any{"authorize_url": upstreamURL})
}

// loadAuthorizedFlow looks up the pending flow row and verifies the caller is
// allowed to act on it. See flowDetail's doc for the deferred-fill exception.
// Writes the appropriate HTTP error and returns a sentinel error on failure.
func (h *MCPSessionsHandler) loadAuthorizedFlow(ctx *fasthttp.RequestCtx, bfCtx *schemas.BifrostContext, flowID string) (*tables.TableOauthUserSession, error) {
	flow, err := h.store.ConfigStore.GetOauthUserSessionByID(ctx, flowID)
	if err != nil {
		logger.Error("[mcp/sessions] load flow failed: flow=%s err=%v", flowID, err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to load OAuth flow")
		return nil, err
	}
	if flow == nil {
		SendError(ctx, fasthttp.StatusNotFound, "OAuth flow not found")
		return nil, errNotFound
	}
	mode, identity := callerModeAndIdentity(bfCtx)
	if !flowAllowsCaller(flow, mode, identity) {
		SendError(ctx, fasthttp.StatusForbidden, "OAuth flow does not belong to your identity")
		return nil, errForbidden
	}
	return flow, nil
}

// flowAllowsCaller returns true when the caller can act on the flow. The
// deferred-fill case (flow_mode=user, user_id=nil) is open to any user-mode
// caller — the completer's identity stamps the row.
func flowAllowsCaller(flow *tables.TableOauthUserSession, mode schemas.AuthMode, identity string) bool {
	flowMode := schemas.AuthMode(flow.FlowMode)
	if flowMode != mode {
		return false
	}
	switch flowMode {
	case schemas.AuthModeUser:
		if flow.UserID == nil || *flow.UserID == "" {
			return identity != "" // deferred-fill; any user-mode caller may complete
		}
		return *flow.UserID == identity
	case schemas.AuthModeVK:
		return flow.VirtualKeyID != nil && *flow.VirtualKeyID == identity
	case schemas.AuthModeNone:
		return flow.SessionToken != "" && flow.SessionToken == identity
	}
	return false
}

// loadAuthorizedToken looks up the row and verifies the caller's identity
// matches. Writes the appropriate HTTP error response on failure and returns
// a sentinel error so callers can early-return.
func (h *MCPSessionsHandler) loadAuthorizedToken(ctx *fasthttp.RequestCtx, rowID string, mode schemas.AuthMode, identity string) (*tables.TableOauthUserToken, error) {
	tok, err := h.store.ConfigStore.GetOauthUserTokenByID(ctx, rowID)
	if err != nil {
		logger.Error("[mcp/sessions] load row failed: token=%s err=%v", rowID, err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to load MCP session")
		return nil, err
	}
	if tok == nil {
		SendError(ctx, fasthttp.StatusNotFound, "MCP session not found")
		return nil, errNotFound
	}
	if !rowMatchesIdentity(tok, mode, identity) {
		SendError(ctx, fasthttp.StatusForbidden, "MCP session does not belong to your identity")
		return nil, errForbidden
	}
	return tok, nil
}

// errNotFound / errForbidden are sentinels used by loadAuthorizedToken so the
// handler can early-return without re-writing the response.
var (
	errNotFound  = errSentinel("not found")
	errForbidden = errSentinel("forbidden")
)

type errSentinel string

func (e errSentinel) Error() string { return string(e) }

// rowMatchesIdentity returns true when the row's identity column for the
// given mode equals the caller's identity. For AuthModeNone the comparison
// is between the caller's session token (raw) and the row's hash, matching
// what the resolver does on lookup.
func rowMatchesIdentity(tok *tables.TableOauthUserToken, mode schemas.AuthMode, identity string) bool {
	switch mode {
	case schemas.AuthModeUser:
		return tok.UserID != nil && *tok.UserID == identity
	case schemas.AuthModeVK:
		return tok.VirtualKeyID != nil && *tok.VirtualKeyID == identity
	case schemas.AuthModeNone:
		return tok.SessionToken != "" && tok.SessionToken == identity
	}
	return false
}

// callerModeAndIdentity extracts the caller's AuthMode and the raw identity
// string for the matching dimension. Mirrors identityForMode in core/mcp/utils
// — kept local because importing across handler→core for this small helper
// would be circular.
func callerModeAndIdentity(bfCtx *schemas.BifrostContext) (schemas.AuthMode, string) {
	mode := bfCtx.AuthMode()
	switch mode {
	case schemas.AuthModeUser:
		if v := bifrost.GetStringFromContext(bfCtx, schemas.BifrostContextKeyUserID); v != "" {
			return mode, v
		}
		// Legacy X-Bf-User-Id back-compat.
		if v := bifrost.GetStringFromContext(bfCtx, schemas.BifrostContextKeyMCPUserID); v != "" {
			return mode, v
		}
	case schemas.AuthModeVK:
		if v := bifrost.GetStringFromContext(bfCtx, schemas.BifrostContextKeyGovernanceVirtualKeyID); v != "" {
			return mode, v
		}
	case schemas.AuthModeNone:
		if v := bifrost.GetStringFromContext(bfCtx, schemas.BifrostContextKeyMCPUserSession); v != "" {
			return mode, v
		}
	}
	return mode, ""
}

// tokenRow maps an oauth_user_tokens row to the wire shape.
func tokenRow(t tables.TableOauthUserToken) mcpSessionRow {
	row := mcpSessionRow{
		ID:            t.ID,
		Kind:          "token",
		AuthMode:      t.AuthMode,
		UserID:        t.UserID,
		VirtualKeyID:  t.VirtualKeyID,
		MCPClientID:   t.MCPClientID,
		Status:        t.Status,
		CreatedAt:     t.CreatedAt.UTC().Format(rfc3339Nano),
		OauthConfigID: t.OauthConfigID,
	}
	if t.ExpiresAt != nil {
		s := t.ExpiresAt.UTC().Format(rfc3339Nano)
		row.ExpiresAt = &s
	}
	return row
}

// flowRow maps an oauth_user_sessions (pending flow) row to the wire shape.
func flowRow(f tables.TableOauthUserSession) mcpSessionRow {
	exp := f.ExpiresAt.UTC().Format(rfc3339Nano)
	return mcpSessionRow{
		ID:            f.ID,
		Kind:          "flow",
		AuthMode:      f.FlowMode,
		UserID:        f.UserID,
		VirtualKeyID:  f.VirtualKeyID,
		MCPClientID:   f.MCPClientID,
		Status:        f.Status,
		ExpiresAt:     &exp,
		CreatedAt:     f.CreatedAt.UTC().Format(rfc3339Nano),
		OauthConfigID: f.OauthConfigID,
	}
}

const rfc3339Nano = "2006-01-02T15:04:05.999999999Z07:00"
