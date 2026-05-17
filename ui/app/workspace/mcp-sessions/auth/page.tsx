// Auth landing route for inline-401 URLs returned by the inference path.
//
// The inference response embeds a frontend URL of the form
//   {base}/workspace/mcp-sessions/auth?flow={flowId}
// pointing here. The page fetches the pending flow's metadata, shows the
// user what they're about to authenticate, and on "Authenticate" click
// asks the backend for the upstream provider authorize URL and redirects
// the browser to it. The upstream provider redirects back to
// /api/oauth/callback which completes the flow server-side.

import FullPageLoader from "@/components/fullPageLoader";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { getErrorMessage, useGetMCPFlowDetailQuery, useStartMCPFlowMutation } from "@/lib/store";
import { Link } from "@tanstack/react-router";
import { ExternalLink, Loader2, ShieldCheck } from "lucide-react";
import { useQueryState } from "nuqs";

export default function MCPSessionsAuthPage() {
	const { toast } = useToast();
	const [flowId] = useQueryState("flow");
	const skip = !flowId;
	const { data: flow, isLoading, isError, error } = useGetMCPFlowDetailQuery(flowId ?? "", { skip });
	const [startFlow, { isLoading: starting }] = useStartMCPFlowMutation();

	if (!flowId) {
		return (
			<CenteredCard>
				<h1 className="text-xl font-semibold">Missing flow identifier</h1>
				<p className="mt-2 text-sm text-muted-foreground">
					This URL is missing the <code className="rounded bg-muted px-1 py-0.5">flow</code> query parameter. Open the link from your
					inference response or the sessions tab.
				</p>
				<div className="mt-6">
					<SessionsTabLink />
				</div>
			</CenteredCard>
		);
	}

	if (isLoading) {
		return <FullPageLoader />;
	}

	if (isError || !flow) {
		const status = (error as { status?: number } | undefined)?.status;
		if (status === 401) {
			return <UnauthenticatedView flowId={flowId} />;
		}
		if (status === 403) {
			return (
				<CenteredCard>
					<h1 className="text-xl font-semibold">This authentication flow isn't yours</h1>
					<p className="mt-2 text-sm text-muted-foreground">
						The pending flow belongs to a different identity. Ask the teammate whose VK or user identity triggered the original
						request to complete it, or trigger a new request yourself.
					</p>
					<div className="mt-6">
						<SessionsTabLink />
					</div>
				</CenteredCard>
			);
		}
		if (status === 404) {
			return (
				<CenteredCard>
					<h1 className="text-xl font-semibold">This authentication flow has expired or been completed</h1>
					<p className="mt-2 text-sm text-muted-foreground">
						Pending flows expire after a short window. If you still need to authenticate, trigger the original action again so a
						fresh flow is created.
					</p>
					<div className="mt-6">
						<SessionsTabLink />
					</div>
				</CenteredCard>
			);
		}
		return (
			<CenteredCard>
				<h1 className="text-xl font-semibold">Could not load this authentication flow</h1>
				<p className="mt-2 text-sm text-muted-foreground">{getErrorMessage(error)}</p>
			</CenteredCard>
		);
	}

	const handleAuthenticate = async () => {
		try {
			const res = await startFlow(flowId).unwrap();
			window.location.href = res.authorize_url;
		} catch (err) {
			toast({ title: "Failed to start authentication", description: getErrorMessage(err), variant: "destructive" });
		}
	};

	return (
		<CenteredCard>
			<div className="mb-4 flex size-12 items-center justify-center rounded-full bg-primary/10">
				<ShieldCheck className="size-6 text-primary" />
			</div>
			<h1 className="text-xl font-semibold">Authenticate with {flow.mcp_client_id}</h1>
			<p className="mt-2 text-sm text-muted-foreground">
				You'll be redirected to the provider to sign in and grant access. Bifrost will store the resulting credential against your{" "}
				{flow.flow_mode === "user" ? "user identity" : flow.flow_mode === "vk" ? "virtual key" : "browser session"} so this request and
				future ones can proceed automatically.
			</p>
			<div className="mt-6 flex gap-3">
				<Button onClick={handleAuthenticate} disabled={starting}>
					{starting ? <Loader2 className="size-4 animate-spin" /> : <ExternalLink className="size-4" />}
					<span className="ml-2">Authenticate</span>
				</Button>
				<SessionsTabLink variant="ghost" />
			</div>
		</CenteredCard>
	);
}

function CenteredCard({ children }: { children: React.ReactNode }) {
	return (
		<div className="mx-auto flex min-h-[60vh] w-full max-w-xl items-center justify-center p-6">
			<div className="w-full rounded-lg border bg-card p-8 shadow-sm">{children}</div>
		</div>
	);
}

function SessionsTabLink({ variant = "outline" }: { variant?: "outline" | "ghost" }) {
	return (
		<Button asChild variant={variant}>
			<Link to="/workspace/mcp-sessions">Open sessions tab</Link>
		</Button>
	);
}

// UnauthenticatedView is the 401 fallback: caller is not logged into the
// dashboard / has no identity in context. Frontend redirects to the dashboard
// login route with a return param so the user lands back here after signing in.
//
// The dashboard-auth-on-but-non-admin-needs-temp-token branch ships in OSS-3
// alongside the temp-token mint endpoint; this OSS-2 cut just sends the user
// to /login and lets the existing login flow handle it.
function UnauthenticatedView({ flowId }: { flowId: string }) {
	const goto = `/workspace/mcp-sessions/auth?flow=${encodeURIComponent(flowId)}`;
	const loginURL = `/login?goto=${encodeURIComponent(goto)}`;
	return (
		<CenteredCard>
			<h1 className="text-xl font-semibold">Sign in to complete authentication</h1>
			<p className="mt-2 text-sm text-muted-foreground">
				Bifrost needs to know who you are before linking this OAuth credential. You'll be sent back here after signing in.
			</p>
			<div className="mt-6">
				<Button asChild>
					<a href={loginURL}>Sign in</a>
				</Button>
			</div>
		</CenteredCard>
	);
}
