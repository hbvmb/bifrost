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

// mcpClientSummary is the minimal MCP client view embedded in session rows.
type mcpClientSummary struct {
	ClientID string `json:"client_id"`
	Name     string `json:"name"`
}

// virtualKeySummary is the minimal VK view embedded in session rows.
type virtualKeySummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// mcpSessionRow is the wire shape for both authenticated tokens and pending flows.
type mcpSessionRow struct {
	ID              string             `json:"id"`
	Kind            string             `json:"kind"` // "token" | "flow"
	AuthMode        string             `json:"auth_mode"`
	UserID          *string            `json:"user_id,omitempty"`
	VirtualKey      *virtualKeySummary `json:"virtual_key,omitempty"`
	MCPClient       *mcpClientSummary  `json:"mcp_client,omitempty"`
	SessionID       *string            `json:"session_id,omitempty"`        // Session-mode identity: caller-issued x-bf-mcp-session-id value
	Status          string             `json:"status"`                      // 'active' | 'orphaned' | 'pending' | 'needs_reauth'
	ExpiresAt       *string            `json:"expires_at,omitempty"`        // RFC3339; nil for non-expiring tokens
	CreatedAt       string             `json:"created_at"`                  // When the session was first authenticated
	LastRefreshedAt *string            `json:"last_refreshed_at,omitempty"` // Token rows only; nil if never refreshed
	OauthConfigID   string             `json:"oauth_config_id,omitempty"`
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

	var (
		tokens []tables.TableOauthUserToken
		flows  []tables.TableOauthUserSession
		err    error
	)
	if identity == "" {
		// No identity on the request (browser/dashboard caller in OSS where
		// there's no user concept). Show every session — the dashboard is the
		// admin view. Enterprise can layer DAC scoping via response middleware.
		tokens, err = h.store.ConfigStore.ListAllOauthUserTokens(ctx, true /*includeOrphaned*/)
		if err == nil {
			flows, err = h.store.ConfigStore.ListAllPendingOauthUserSessions(ctx)
		}
	} else {
		// Identity present (VK header, SCIM JWT, etc.) — return only sessions
		// keyed by that identity column.
		tokens, err = h.store.ConfigStore.ListOauthUserTokensByMode(ctx, mode, identity, true /*includeOrphaned*/)
		if err == nil {
			flows, err = h.store.ConfigStore.ListOauthUserSessionsByMode(ctx, mode, identity)
		}
	}
	if err != nil {
		logger.Error("[mcp/sessions] list failed: %v", err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to list MCP sessions")
		return
	}

	// A reauth in flight produces a token row (the live credential) and a
	// pending flow row (the in-flight OAuth attempt) for the same binding.
	// They're conceptually the same identity — surface the token row only and
	// suppress the flow row to avoid confusing duplicates in the UI. The flow
	// row is still in the DB; once the callback completes it moves to status
	// 'authorized' and stops being returned by the pending-flow query anyway.
	tokenBindings := make(map[sessionBindingKey]struct{}, len(tokens))
	for _, t := range tokens {
		tokenBindings[bindingKeyFromToken(t)] = struct{}{}
	}

	rows := make([]mcpSessionRow, 0, len(tokens)+len(flows))
	for _, t := range tokens {
		rows = append(rows, tokenRow(t))
	}
	for _, f := range flows {
		if _, hasToken := tokenBindings[bindingKeyFromFlow(f)]; hasToken {
			continue
		}
		rows = append(rows, flowRow(f))
	}
	SendJSON(ctx, mcpSessionsListResponse{Sessions: rows})
}

type sessionBindingKey struct {
	Mode        string
	Identity    string
	MCPClientID string
}

func bindingKeyFromToken(t tables.TableOauthUserToken) sessionBindingKey {
	k := sessionBindingKey{Mode: t.AuthMode, MCPClientID: t.MCPClientID}
	switch schemas.AuthMode(t.AuthMode) {
	case schemas.AuthModeUser:
		if t.UserID != nil {
			k.Identity = *t.UserID
		}
	case schemas.AuthModeVK:
		if t.VirtualKeyID != nil {
			k.Identity = *t.VirtualKeyID
		}
	case schemas.AuthModeSession:
		k.Identity = t.SessionID
	}
	return k
}

func bindingKeyFromFlow(f tables.TableOauthUserSession) sessionBindingKey {
	k := sessionBindingKey{Mode: f.FlowMode, MCPClientID: f.MCPClientID}
	switch schemas.AuthMode(f.FlowMode) {
	case schemas.AuthModeUser:
		if f.UserID != nil {
			k.Identity = *f.UserID
		}
	case schemas.AuthModeVK:
		if f.VirtualKeyID != nil {
			k.Identity = *f.VirtualKeyID
		}
	case schemas.AuthModeSession:
		k.Identity = f.SessionID
	}
	return k
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

	tok, err := h.loadRowAuthorizedForCaller(ctx, bfCtx, rowID)
	if err != nil {
		// loadRowAuthorizedForCaller already wrote the error response.
		_ = err
		return
	}

	// The new flow must reuse the existing row's identity so the callback's
	// upsert lands on the same (identity, mcp_client) row. Inject the row's
	// values into context; InitiateUserOAuthFlow reads them per-mode.
	rowMode := schemas.AuthMode(tok.AuthMode)
	switch rowMode {
	case schemas.AuthModeSession:
		if tok.SessionID != "" {
			bfCtx.SetValue(schemas.BifrostContextKeyMCPSessionID, tok.SessionID)
		}
	case schemas.AuthModeVK:
		if tok.VirtualKeyID != nil && *tok.VirtualKeyID != "" {
			bfCtx.SetValue(schemas.BifrostContextKeyGovernanceVirtualKeyID, *tok.VirtualKeyID)
		}
	case schemas.AuthModeUser:
		if tok.UserID != nil && *tok.UserID != "" {
			bfCtx.SetValue(schemas.BifrostContextKeyUserID, *tok.UserID)
		}
	}

	provider := h.store.OAuthProvider
	if provider == nil {
		SendError(ctx, fasthttp.StatusServiceUnavailable, "OAuth provider not configured")
		return
	}
	redirectURI := lib.BuildBaseURL(ctx, h.store.GetMCPExternalClientURL()) + "/api/oauth/callback"
	flow, sessionID, err := provider.InitiateUserOAuthFlow(bfCtx, tok.OauthConfigID, tok.MCPClientID, redirectURI, rowMode)
	if err != nil {
		logger.Error("[mcp/sessions] reauth flow init failed: token=%s err=%v", rowID, err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to initiate reauthentication")
		return
	}
	logger.Info("[mcp/sessions] reauth initiated: token=%s mcp_client=%s mode=%s flow=%s", rowID, tok.MCPClientID, rowMode, sessionID)
	SendJSON(ctx, map[string]any{
		"authorize_url": flow.AuthorizeURL,
		"session_id":    sessionID,
	})
}

// revoke best-effort revokes the upstream token and hard-deletes the row.
// Same authorization model as list/reauth: caller with an identity must match
// the row's identity column; caller without an identity is the dashboard admin
// view and can act on any row.
func (h *MCPSessionsHandler) revoke(ctx *fasthttp.RequestCtx) {
	rowID, ok := ctx.UserValue("id").(string)
	if !ok || rowID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid session id")
		return
	}
	bfCtx, cancel := lib.ConvertToBifrostContext(ctx, h.store)
	defer cancel()

	tok, err := h.loadRowAuthorizedForCaller(ctx, bfCtx, rowID)
	if err != nil {
		_ = err
		return
	}

	// Best-effort upstream revoke via the session token (which keys the
	// RefreshUserAccessToken / RevokeUserToken path).
	if tok.SessionID != "" {
		if revokeErr := h.store.OAuthProvider.RevokeUserToken(ctx, tok.SessionID); revokeErr != nil {
			logger.Warn("[mcp/sessions] upstream revoke failed (continuing with row delete): token=%s err=%v", rowID, revokeErr)
		}
	}

	if err := h.store.ConfigStore.DeleteOauthUserToken(ctx, tok.ID); err != nil {
		logger.Error("[mcp/sessions] delete row failed: token=%s err=%v", rowID, err)
		SendError(ctx, fasthttp.StatusInternalServerError, "Failed to delete MCP session")
		return
	}
	// Also clear any flow rows tied to this row's identity + MCP client.
	// For session mode this prevents the next OAuth init from upserting a
	// stale row; for vk/user modes it keeps the table clean by removing
	// previously-authorized flow rows that would otherwise linger forever.
	rowMode, rowIdentity := identityFromTokenRow(tok)
	if rowIdentity != "" {
		if delErr := h.store.ConfigStore.DeleteOauthUserSessionsByModeIdentityAndMCPClient(ctx, rowMode, rowIdentity, tok.MCPClientID); delErr != nil {
			logger.Warn("[mcp/sessions] clearing flow rows failed (token already deleted): token=%s err=%v", rowID, delErr)
		}
	}
	logger.Info("[mcp/sessions] revoked: token=%s mcp_client=%s mode=%s", rowID, tok.MCPClientID, tok.AuthMode)
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}

// mcpFlowDetailResponse is the wire shape for GET /api/oauth/per-user/flows/{id}.
type mcpFlowDetailResponse struct {
	ID            string             `json:"id"`
	FlowMode      string             `json:"flow_mode"`
	Status        string             `json:"status"`
	MCPClient     *mcpClientSummary  `json:"mcp_client,omitempty"`
	OauthConfigID string             `json:"oauth_config_id"`
	UserID        *string            `json:"user_id,omitempty"`
	VirtualKey    *virtualKeySummary `json:"virtual_key,omitempty"`
	ExpiresAt     string             `json:"expires_at"`
	CreatedAt     string             `json:"created_at"`
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
	resp := mcpFlowDetailResponse{
		ID:            flow.ID,
		FlowMode:      flow.FlowMode,
		Status:        flow.Status,
		OauthConfigID: flow.OauthConfigID,
		UserID:        flow.UserID,
		ExpiresAt:     flow.ExpiresAt.UTC().Format(rfc3339Nano),
		CreatedAt:     flow.CreatedAt.UTC().Format(rfc3339Nano),
	}
	if flow.MCPClient != nil {
		resp.MCPClient = &mcpClientSummary{ClientID: flow.MCPClient.ClientID, Name: flow.MCPClient.Name}
	} else {
		resp.MCPClient = &mcpClientSummary{ClientID: flow.MCPClientID}
	}
	if flow.VirtualKey != nil {
		resp.VirtualKey = &virtualKeySummary{ID: flow.VirtualKey.ID, Name: flow.VirtualKey.Name}
	} else if flow.VirtualKeyID != nil {
		resp.VirtualKey = &virtualKeySummary{ID: *flow.VirtualKeyID}
	}
	SendJSON(ctx, resp)
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

// flowAllowsCaller returns true when the caller can act on the flow.
//
// Authorization model:
//   - vk-mode: open to anyone who has the flow ID. The VK is a shared
//     credential; possession of the (opaque, short-lived) flow ID is the
//     authorization. Enterprise can layer stricter DAC scoping on top via
//     response middleware.
//   - session-mode: same model as vk-mode. The flow's SessionToken was set
//     from the originating caller's x-bf-mcp-session-id header; the browser
//     opening the auth URL won't (and shouldn't have to) carry that header,
//     so possession of the flow ID is the authorization. The token row
//     created at completion stays keyed by the original session ID.
//   - user-mode pre-populated: only the same user can complete.
//   - user-mode deferred-fill: any authenticated user may complete; their
//     identity stamps the row at completion time.
func flowAllowsCaller(flow *tables.TableOauthUserSession, mode schemas.AuthMode, identity string) bool {
	flowMode := schemas.AuthMode(flow.FlowMode)
	switch flowMode {
	case schemas.AuthModeVK, schemas.AuthModeSession:
		return true
	case schemas.AuthModeUser:
		if mode != schemas.AuthModeUser {
			return false
		}
		if flow.UserID == nil || *flow.UserID == "" {
			return identity != "" // deferred-fill; any user-mode caller may complete
		}
		return *flow.UserID == identity
	}
	return false
}

// identityFromTokenRow returns the (mode, identity) pair recorded on the row.
// Inverse of the mode/identity routing used when creating the row; the row's
// AuthMode column is the source of truth for which identity column is keyed.
func identityFromTokenRow(tok *tables.TableOauthUserToken) (schemas.AuthMode, string) {
	switch schemas.AuthMode(tok.AuthMode) {
	case schemas.AuthModeUser:
		if tok.UserID != nil {
			return schemas.AuthModeUser, *tok.UserID
		}
	case schemas.AuthModeVK:
		if tok.VirtualKeyID != nil {
			return schemas.AuthModeVK, *tok.VirtualKeyID
		}
	case schemas.AuthModeSession:
		return schemas.AuthModeSession, tok.SessionID
	}
	return schemas.AuthMode(tok.AuthMode), ""
}

// loadRowAuthorizedForCaller loads a token row and applies the same
// authorization model used by list: callers with an identity must match the
// row's identity column; callers without an identity (dashboard admin view)
// can act on any row. Writes the HTTP error response on failure.
func (h *MCPSessionsHandler) loadRowAuthorizedForCaller(ctx *fasthttp.RequestCtx, bfCtx *schemas.BifrostContext, rowID string) (*tables.TableOauthUserToken, error) {
	mode, identity := callerModeAndIdentity(bfCtx)
	if identity == "" {
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
		return tok, nil
	}
	return h.loadAuthorizedToken(ctx, rowID, mode, identity)
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
// given mode equals the caller's identity. For AuthModeSession the comparison
// is between the caller's session token (raw) and the row's hash, matching
// what the resolver does on lookup.
func rowMatchesIdentity(tok *tables.TableOauthUserToken, mode schemas.AuthMode, identity string) bool {
	switch mode {
	case schemas.AuthModeUser:
		return tok.UserID != nil && *tok.UserID == identity
	case schemas.AuthModeVK:
		return tok.VirtualKeyID != nil && *tok.VirtualKeyID == identity
	case schemas.AuthModeSession:
		return tok.SessionID != "" && tok.SessionID == identity
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
	case schemas.AuthModeSession:
		if v := bifrost.GetStringFromContext(bfCtx, schemas.BifrostContextKeyMCPSessionID); v != "" {
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
		Status:        t.Status,
		CreatedAt:     t.CreatedAt.UTC().Format(rfc3339Nano),
		OauthConfigID: t.OauthConfigID,
	}
	if t.MCPClient != nil {
		row.MCPClient = &mcpClientSummary{ClientID: t.MCPClient.ClientID, Name: t.MCPClient.Name}
	} else {
		row.MCPClient = &mcpClientSummary{ClientID: t.MCPClientID}
	}
	if t.VirtualKey != nil {
		row.VirtualKey = &virtualKeySummary{ID: t.VirtualKey.ID, Name: t.VirtualKey.Name}
	} else if t.VirtualKeyID != nil {
		row.VirtualKey = &virtualKeySummary{ID: *t.VirtualKeyID}
	}
	if t.AuthMode == string(schemas.AuthModeSession) && t.SessionID != "" {
		s := t.SessionID
		row.SessionID = &s
	}
	if t.ExpiresAt != nil {
		s := t.ExpiresAt.UTC().Format(rfc3339Nano)
		row.ExpiresAt = &s
	}
	if t.LastRefreshedAt != nil {
		s := t.LastRefreshedAt.UTC().Format(rfc3339Nano)
		row.LastRefreshedAt = &s
	}
	return row
}

// flowRow maps an oauth_user_sessions (pending flow) row to the wire shape.
func flowRow(f tables.TableOauthUserSession) mcpSessionRow {
	exp := f.ExpiresAt.UTC().Format(rfc3339Nano)
	row := mcpSessionRow{
		ID:            f.ID,
		Kind:          "flow",
		AuthMode:      f.FlowMode,
		UserID:        f.UserID,
		Status:        f.Status,
		ExpiresAt:     &exp,
		CreatedAt:     f.CreatedAt.UTC().Format(rfc3339Nano),
		OauthConfigID: f.OauthConfigID,
	}
	if f.MCPClient != nil {
		row.MCPClient = &mcpClientSummary{ClientID: f.MCPClient.ClientID, Name: f.MCPClient.Name}
	} else {
		row.MCPClient = &mcpClientSummary{ClientID: f.MCPClientID}
	}
	if f.VirtualKey != nil {
		row.VirtualKey = &virtualKeySummary{ID: f.VirtualKey.ID, Name: f.VirtualKey.Name}
	} else if f.VirtualKeyID != nil {
		row.VirtualKey = &virtualKeySummary{ID: *f.VirtualKeyID}
	}
	if f.FlowMode == string(schemas.AuthModeSession) && f.SessionID != "" {
		s := f.SessionID
		row.SessionID = &s
	}
	return row
}

const rfc3339Nano = "2006-01-02T15:04:05.999999999Z07:00"
