// Types for the MCP Auth Sessions tab + auth landing flow.
// Mirrors the wire shapes in transports/bifrost-http/handlers/mcp_sessions.go.

export type AuthMode = "user" | "vk" | "none";

export type MCPSessionKind = "token" | "flow";

// Status values vary by Kind:
//   token:  "active" | "orphaned"
//   flow:   "pending" (only pending flows are surfaced; expired/completed are not)
export type MCPSessionStatus = "active" | "orphaned" | "pending";

export interface MCPSessionRow {
	id: string;
	kind: MCPSessionKind;
	auth_mode: AuthMode;
	user_id?: string | null;
	virtual_key_id?: string | null;
	mcp_client_id: string;
	status: MCPSessionStatus;
	expires_at?: string | null;
	created_at: string;
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
	status: "pending" | "authorized" | "failed" | "expired";
	mcp_client_id: string;
	oauth_config_id: string;
	user_id?: string | null;
	virtual_key_id?: string | null;
	expires_at: string;
	created_at: string;
}

export interface MCPFlowStartResponse {
	authorize_url: string;
}
