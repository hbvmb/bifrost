// Base sessions table: renders token rows + pending flow rows visible to
// the caller's identity. VK-keyed rows render directly with their VK ID;
// user-keyed rows render enterprise enrichment slots (granted-via VK chips +
// user display) which the OSS bundle stubs out as no-ops.
//
// Status badges:
//   active:   token row, usable
//   orphaned: token row, no granting VK anymore; needs re-auth
//   pending:  flow row, user must complete authentication

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
	AlertDialog,
	AlertDialogAction,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
} from "@/components/ui/alertDialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdownMenu";
import { PIN_SHADOW_RIGHT } from "@/components/table/columnPinning";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Info } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { getErrorMessage, useReauthMCPSessionMutation, useRevokeMCPSessionMutation } from "@/lib/store";
import { MCPSessionRow } from "@/lib/types/mcpSessions";
import GrantedViaVKChips from "@enterprise/components/mcp-sessions/grantedViaVKChips";
import UserDisplay from "@enterprise/components/mcp-sessions/userDisplay";
import { ExternalLink, Fingerprint, KeyRound, Loader2, MoreHorizontal, RefreshCcw, Trash2, UserRound } from "lucide-react";
import { useState } from "react";

interface SessionsTableProps {
	sessions: MCPSessionRow[];
}

export default function SessionsTable({ sessions }: SessionsTableProps) {
	const { toast } = useToast();
	const [reauth, { isLoading: reauthing }] = useReauthMCPSessionMutation();
	const [revoke, { isLoading: revoking }] = useRevokeMCPSessionMutation();
	const [pendingDelete, setPendingDelete] = useState<MCPSessionRow | null>(null);

	const handleReauth = async (row: MCPSessionRow) => {
		try {
			const res = await reauth(row.id).unwrap();
			// Open the upstream authorize URL. User completes there, then
			// is redirected back to /api/oauth/callback by the provider.
			window.location.href = res.authorize_url;
		} catch (err) {
			toast({ title: "Re-authentication failed", description: getErrorMessage(err), variant: "destructive" });
		}
	};

	const confirmRevoke = async () => {
		if (!pendingDelete) return;
		const row = pendingDelete;
		setPendingDelete(null);
		try {
			await revoke(row.id).unwrap();
			toast({ title: "Session revoked" });
		} catch (err) {
			toast({ title: "Failed to revoke session", description: getErrorMessage(err), variant: "destructive" });
		}
	};

	return (
		<div className="space-y-4">
			<AlertDialog open={pendingDelete !== null} onOpenChange={(open) => !open && setPendingDelete(null)}>
				<AlertDialogContent>
					<AlertDialogHeader>
						<AlertDialogTitle>Revoke this MCP session?</AlertDialogTitle>
						<AlertDialogDescription>
							Bifrost will attempt to revoke the upstream OAuth token and remove the stored credential. Anyone using this binding
							will need to re-authenticate.
						</AlertDialogDescription>
					</AlertDialogHeader>
					<AlertDialogFooter>
						<AlertDialogCancel>Cancel</AlertDialogCancel>
						<AlertDialogAction onClick={confirmRevoke}>Revoke</AlertDialogAction>
					</AlertDialogFooter>
				</AlertDialogContent>
			</AlertDialog>

			<div className="flex items-center justify-between gap-4">
				<div>
					<h2 className="text-lg font-semibold tracking-tight">MCP Auth Sessions</h2>
					<p className="text-muted-foreground text-sm">
						Per-user OAuth tokens stored for MCP servers, plus any pending authentication flows.
					</p>
				</div>
			</div>

			<div className="overflow-auto rounded-sm border">
				<Table>
					<TableHeader>
						<TableRow>
							<TableHead>MCP Client</TableHead>
							<TableHead>
								<HeaderWithTooltip
									label="Bound to"
									tooltip="The identity this OAuth token is keyed to: an end user (via SSO), a virtual key (shared by anyone using that VK), or a client-issued session ID (asserted via the x-bf-mcp-session-id header)."
								/>
							</TableHead>
							<TableHead>
								<HeaderWithTooltip
									label="Status"
									tooltip="Active = ready to use. Pending = OAuth flow started, user must complete it. Re-auth required = refresh token was rejected upstream; user must reconnect. Orphaned = a user lost their last access path to this MCP client (no remaining VK grants it); row kept for visibility but never used."
								/>
							</TableHead>
							<TableHead>
								<HeaderWithTooltip
									label="Access token expiry"
									tooltip="When the current access token expires. Bifrost auto-refreshes using the refresh token on the next request, so an active row past its expiry will silently mint a new token at use time."
								/>
							</TableHead>
							<TableHead>Created</TableHead>
							<TableHead className={`bg-muted sticky right-0 z-10 w-[56px] text-right ${PIN_SHADOW_RIGHT}`}></TableHead>
						</TableRow>
					</TableHeader>
					<TableBody>
						{sessions.length === 0 ? (
							<TableRow>
								<TableCell colSpan={6} className="h-24 text-center">
									<span className="text-muted-foreground text-sm">
										No sessions yet. Sessions appear here when an inference request or MCP gateway call triggers per-user OAuth.
									</span>
								</TableCell>
							</TableRow>
						) : (
							sessions.map((row) => (
								<TableRow key={`${row.kind}-${row.id}`} className="group">
									<TableCell className="font-medium">{row.mcp_client?.name || row.mcp_client?.client_id || "-"}</TableCell>
									<TableCell>
										<BindingCell row={row} />
									</TableCell>
									<TableCell>
										<StatusBadge status={row.status} kind={row.kind} />
									</TableCell>
									<TableCell className="text-muted-foreground text-sm">
										<div className="flex flex-col">
											<span>{formatAccessExpiry(row)}</span>
											{row.last_refreshed_at ? (
												<span className="text-xs">refreshed {formatRelativePast(row.last_refreshed_at)}</span>
											) : null}
										</div>
									</TableCell>
									<TableCell className="text-muted-foreground text-sm">{formatRelativePast(row.created_at)}</TableCell>
									<TableCell
										className={`group-hover:bg-muted dark:bg-card dark:group-hover:bg-muted sticky right-0 z-10 bg-white text-right ${PIN_SHADOW_RIGHT}`}
									>
										<RowActions
											row={row}
											reauthing={reauthing}
											revoking={revoking}
											onReauth={() => handleReauth(row)}
											onRevoke={() => setPendingDelete(row)}
										/>
									</TableCell>
								</TableRow>
							))
						)}
					</TableBody>
				</Table>
			</div>
		</div>
	);
}

function HeaderWithTooltip({ label, tooltip }: { label: string; tooltip: string }) {
	return (
		<TooltipProvider delayDuration={150}>
			<Tooltip>
				<TooltipTrigger asChild>
					<span className="inline-flex cursor-help items-center gap-2">
						{label}
						<Info className="size-3 text-muted-foreground" />
					</span>
				</TooltipTrigger>
				<TooltipContent className="max-w-xs">{tooltip}</TooltipContent>
			</Tooltip>
		</TooltipProvider>
	);
}

function BindingCell({ row }: { row: MCPSessionRow }) {
	if (row.auth_mode === "user" && row.user_id) {
		return (
			<div className="flex flex-col gap-1">
				<div className="flex items-center gap-1.5 text-sm">
					<UserRound className="size-3.5 text-muted-foreground" />
					<UserDisplay userId={row.user_id} fallback={<span className="font-mono">{row.user_id}</span>} />
				</div>
				<GrantedViaVKChips userId={row.user_id} mcpClientId={row.mcp_client?.client_id ?? ""} />
			</div>
		);
	}
	if (row.auth_mode === "vk" && row.virtual_key) {
		return (
			<div className="flex items-center gap-1.5 text-sm">
				<KeyRound className="size-3.5 text-muted-foreground" />
				<span>{row.virtual_key.name || row.virtual_key.id}</span>
			</div>
		);
	}
	if (row.auth_mode === "session" && row.session_id) {
		return (
			<div className="flex items-center gap-1.5 text-sm">
				<Fingerprint className="size-3.5 text-muted-foreground" />
				<span className="font-mono">{row.session_id}</span>
			</div>
		);
	}
	return <span className="text-sm text-muted-foreground">Session-bound</span>;
}

function StatusBadge({ status, kind }: { status: string; kind: string }) {
	if (kind === "flow") {
		if (status === "needs_reauth") {
			return <Badge variant="destructive">Re-auth required</Badge>;
		}
		return <Badge variant="secondary">Pending</Badge>;
	}
	if (status === "orphaned") {
		return <Badge variant="destructive">Needs re-auth</Badge>;
	}
	return <Badge>Active</Badge>;
}

interface RowActionsProps {
	row: MCPSessionRow;
	reauthing: boolean;
	revoking: boolean;
	onReauth: () => void;
	onRevoke: () => void;
}

function RowActions({ row, reauthing, revoking, onReauth, onRevoke }: RowActionsProps) {
	const busy = reauthing || revoking;
	return (
		<DropdownMenu>
			<DropdownMenuTrigger asChild>
				<Button variant="ghost" size="icon" className="h-8 w-8" aria-label="MCP session actions">
					{busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <MoreHorizontal className="h-4 w-4" />}
				</Button>
			</DropdownMenuTrigger>
			<DropdownMenuContent align="end">
				{row.kind === "flow" ? (
					row.status === "needs_reauth" ? (
						// The PKCE state on this flow row is dead; a fresh request to the
						// MCP client will start a new flow. No action we can offer wires
						// up to the existing flow row, so surface guidance instead.
						<DropdownMenuItem disabled className="cursor-default text-xs text-muted-foreground">
							Trigger a request to re-authenticate
						</DropdownMenuItem>
					) : (
						<DropdownMenuItem
							className="cursor-pointer"
							onSelect={(e) => {
								e.preventDefault();
								window.location.href = `/workspace/mcp-sessions/auth?flow=${row.id}`;
							}}
						>
							<ExternalLink className="h-4 w-4" />
							Complete authentication
						</DropdownMenuItem>
					)
				) : (
					<>
						<DropdownMenuItem
							className="cursor-pointer"
							disabled={reauthing}
							onSelect={(e) => {
								e.preventDefault();
								onReauth();
							}}
						>
							<RefreshCcw className="h-4 w-4" />
							Re-authenticate
						</DropdownMenuItem>
						<DropdownMenuItem
							variant="destructive"
							className="cursor-pointer"
							onSelect={(e) => {
								e.preventDefault();
								onRevoke();
							}}
						>
							<Trash2 className="h-4 w-4" />
							Revoke
						</DropdownMenuItem>
					</>
				)}
			</DropdownMenuContent>
		</DropdownMenu>
	);
}

function formatRelativePast(iso: string): string {
	try {
		const diffMs = Date.now() - new Date(iso).getTime();
		if (diffMs < 60_000) return "just now";
		const mins = Math.floor(diffMs / 60_000);
		if (mins < 60) return `${mins} min ago`;
		const hours = Math.floor(diffMs / 3_600_000);
		if (hours < 48) return `${hours}h ago`;
		const days = Math.floor(diffMs / 86_400_000);
		return `${days}d ago`;
	} catch {
		return iso;
	}
}

function formatAccessExpiry(row: MCPSessionRow): string {
	if (!row.expires_at) return "-";
	try {
		const d = new Date(row.expires_at);
		const diffMs = d.getTime() - Date.now();
		if (diffMs < 0) {
			// Active rows auto-refresh on next use via the refresh token,
			// don't scare the user with "expired" for what's actually a healthy session.
			return row.status === "active" ? "Refreshes on next use" : "expired";
		}
		const days = Math.floor(diffMs / 86_400_000);
		if (days > 1) return `in ${days} days`;
		const hours = Math.floor(diffMs / 3_600_000);
		if (hours > 1) return `in ${hours} hours`;
		const mins = Math.floor(diffMs / 60_000);
		return `in ${Math.max(mins, 1)} min`;
	} catch {
		return row.expires_at;
	}
}
