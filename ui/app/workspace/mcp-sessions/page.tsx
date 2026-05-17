import FullPageLoader from "@/components/fullPageLoader";
import { getErrorMessage, useGetMCPSessionsQuery } from "@/lib/store";
import SessionsTable from "./views/sessionsTable";

export default function MCPSessionsPage() {
	const { data, isLoading, isError, error } = useGetMCPSessionsQuery();

	if (isLoading) {
		return <FullPageLoader />;
	}

	if (isError) {
		return (
			<div className="rounded-lg border border-destructive bg-destructive/10 p-6 text-sm text-destructive">
				Failed to load MCP sessions: {getErrorMessage(error)}
			</div>
		);
	}

	return (
		<div className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-6">
			<header>
				<h1 className="text-2xl font-semibold tracking-tight">MCP Auth Sessions</h1>
				<p className="mt-1 text-sm text-muted-foreground">
					Per-user OAuth tokens stored for MCP servers, plus any pending authentication flows.
				</p>
			</header>
			<SessionsTable sessions={data?.sessions ?? []} />
		</div>
	);
}
