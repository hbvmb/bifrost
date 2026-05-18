// Types for the MCP Auth Sessions tab + auth landing flow.
// Mirrors the wire shapes in transports/bifrost-http/handlers/mcp_sessions.go.

export type AuthMode = "user" | "vk" | "session";

export type MCPSessionKind = "token" | "flow";

// Status values vary by Kind:
//   token:  "active" | "orphaned"
//   flow:   "pending" | "needs_reauth"
//     - "pending":      fresh auth in progress; user must complete OAuth
//     - "needs_reauth": refresh token died upstream; the token row was deleted
//                       and this flow row is the marker telling the user to
//                       reconnect. The original PKCE state is dead; the user
//                       must initiate a new flow (next inference call will).
export type MCPSessionStatus = "active" | "orphaned" | "pending" | "needs_reauth";

export interface MCPClientSummary {
	client_id: string;
	name: string;
}

export interface VirtualKeySummary {
	id: string;
	name: string;
}

export interface MCPSessionRow {
	id: string;
	kind: MCPSessionKind;
	auth_mode: AuthMode;
	user_id?: string | null;
	virtual_key?: VirtualKeySummary | null;
	mcp_client?: MCPClientSummary | null;
	session_id?: string | null;
	status: MCPSessionStatus;
	expires_at?: string | null;
	created_at: string;
	last_refreshed_at?: string | null;
	oauth_config_id?: string;
}

export interface MCPSessionsListResponse {
	sessions: MCPSessionRow[];
}

export interface MCPSessionReauthResponse {
	authorize_url: string;
	session_id: string;
}

export interface MCPFlowDetail {
	id: string;
	flow_mode: AuthMode;
	status: "pending" | "authorized" | "failed" | "expired" | "needs_reauth";
	mcp_client?: MCPClientSummary | null;
	oauth_config_id: string;
	user_id?: string | null;
	virtual_key?: VirtualKeySummary | null;
	session_id?: string | null;
	expires_at: string;
	created_at: string;
	// True when an active token already exists for this binding. Combined with
	// status='pending' it means OAuth was re-initiated unnecessarily — the
	// auth page should treat it as already authenticated.
	has_active_token?: boolean;
}

export interface MCPFlowStartResponse {
	authorize_url: string;
}
