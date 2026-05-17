import { createFileRoute } from "@tanstack/react-router";
import MCPSessionsPage from "./page";

function RouteComponent() {
	// Per-user OAuth sessions are scoped to the caller's own identity on the
	// backend, so any authenticated dashboard user can view their tab. No RBAC
	// resource yet — enterprise can layer DAC scoping on top of the API.
	return <MCPSessionsPage />;
}

export const Route = createFileRoute("/workspace/mcp-sessions")({
	component: RouteComponent,
});
