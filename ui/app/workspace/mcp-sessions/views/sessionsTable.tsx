// Base sessions table — renders token rows + pending flow rows visible to
// the caller's identity. VK-keyed rows render directly with their VK ID;
// user-keyed rows render enterprise enrichment slots (granted-via VK chips +
// user display) which the OSS bundle stubs out as no-ops.
//
// Status badges:
//   active   — token row, usable
//   orphaned — token row, no granting VK anymore; needs re-auth
//   pending  — flow row, user must complete authentication

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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import {
	getErrorMessage,
	useReauthMCPSessionMutation,
	useRevokeMCPSessionMutation,
} from "@/lib/store";
import { MCPSessionRow } from "@/lib/types/mcpSessions";
import GrantedViaVKChips from "@enterprise/components/mcp-sessions/grantedViaVKChips";
import UserDisplay from "@enterprise/components/mcp-sessions/userDisplay";
import { KeyRound, Loader2, RefreshCcw, Trash2, UserRound } from "lucide-react";
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
			// Open the upstream authorize URL — user completes there, then
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

	if (sessions.length === 0) {
		return (
			<div className="rounded-lg border bg-card p-12 text-center text-sm text-muted-foreground">
				<p>No MCP sessions yet.</p>
				<p className="mt-2">Sessions appear here when an inference request or MCP gateway call triggers per-user OAuth.</p>
			</div>
		);
	}

	return (
		<>
			<Table>
				<TableHeader>
					<TableRow>
						<TableHead>MCP Client</TableHead>
						<TableHead>Bound to</TableHead>
						<TableHead>Status</TableHead>
						<TableHead>Expires</TableHead>
						<TableHead className="text-right">Actions</TableHead>
					</TableRow>
				</TableHeader>
				<TableBody>
					{sessions.map((row) => (
						<TableRow key={`${row.kind}-${row.id}`}>
							<TableCell className="font-medium">{row.mcp_client_id}</TableCell>
							<TableCell>
								<BindingCell row={row} />
							</TableCell>
							<TableCell>
								<StatusBadge status={row.status} kind={row.kind} />
							</TableCell>
							<TableCell className="text-muted-foreground text-sm">
								{row.expires_at ? formatExpiresAt(row.expires_at) : "—"}
							</TableCell>
							<TableCell className="text-right">
								<RowActions
									row={row}
									reauthing={reauthing}
									revoking={revoking}
									onReauth={() => handleReauth(row)}
									onRevoke={() => setPendingDelete(row)}
								/>
							</TableCell>
						</TableRow>
					))}
				</TableBody>
			</Table>

			<AlertDialog open={pendingDelete !== null} onOpenChange={(open) => !open && setPendingDelete(null)}>
				<AlertDialogContent>
					<AlertDialogHeader>
						<AlertDialogTitle>Revoke this MCP session?</AlertDialogTitle>
						<AlertDialogDescription>
							Bifrost will attempt to revoke the upstream OAuth token and remove the stored credential. Anyone using this binding will need to re-authenticate.
						</AlertDialogDescription>
					</AlertDialogHeader>
					<AlertDialogFooter>
						<AlertDialogCancel>Cancel</AlertDialogCancel>
						<AlertDialogAction onClick={confirmRevoke}>Revoke</AlertDialogAction>
					</AlertDialogFooter>
				</AlertDialogContent>
			</AlertDialog>
		</>
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
				<GrantedViaVKChips userId={row.user_id} mcpClientId={row.mcp_client_id} />
			</div>
		);
	}
	if (row.auth_mode === "vk" && row.virtual_key_id) {
		return (
			<div className="flex items-center gap-1.5 text-sm">
				<KeyRound className="size-3.5 text-muted-foreground" />
				<span className="font-mono">{row.virtual_key_id}</span>
				<span className="text-xs text-muted-foreground">(shared by anyone with this VK)</span>
			</div>
		);
	}
	return <span className="text-sm text-muted-foreground">Anonymous session</span>;
}

function StatusBadge({ status, kind }: { status: string; kind: string }) {
	if (kind === "flow") {
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
	// Pending flow rows have a single action: complete authentication.
	// Their /reauth is irrelevant (the flow itself is what they'd complete).
	if (row.kind === "flow") {
		return (
			<Button
				size="sm"
				variant="outline"
				onClick={() => {
					window.location.href = `/workspace/mcp-sessions/auth?flow=${row.id}`;
				}}
			>
				Complete authentication
			</Button>
		);
	}
	return (
		<div className="flex justify-end gap-2">
			<Button size="sm" variant="outline" onClick={onReauth} disabled={reauthing}>
				{reauthing ? <Loader2 className="size-3.5 animate-spin" /> : <RefreshCcw className="size-3.5" />}
				<span className="ml-1">Re-authenticate</span>
			</Button>
			<Button size="sm" variant="destructive" onClick={onRevoke} disabled={revoking}>
				<Trash2 className="size-3.5" />
				<span className="ml-1">Revoke</span>
			</Button>
		</div>
	);
}

function formatExpiresAt(iso: string): string {
	try {
		const d = new Date(iso);
		const now = Date.now();
		const diffMs = d.getTime() - now;
		if (diffMs < 0) return "expired";
		const days = Math.floor(diffMs / 86_400_000);
		if (days > 1) return `in ${days} days`;
		const hours = Math.floor(diffMs / 3_600_000);
		if (hours > 1) return `in ${hours} hours`;
		const mins = Math.floor(diffMs / 60_000);
		return `in ${Math.max(mins, 1)} min`;
	} catch {
		return iso;
	}
}
