// OSS-only fallback. The enterprise build replaces this with a component that
// joins the user's access profiles → virtual keys → MCP allowlists to render
// "granted via" chips for user-keyed sessions. OSS has no user→VK ownership
// concept, so this slot is intentionally empty.

interface GrantedViaVKChipsProps {
	userId: string;
	mcpClientId: string;
}

export default function GrantedViaVKChips(_props: GrantedViaVKChipsProps) {
	return null;
}
