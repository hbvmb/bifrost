// OSS-only fallback. The enterprise build replaces this with a component that
// fetches the SCIM user record for the given user_id and renders name/email.
// OSS has no user table; we just render the raw user_id provided via fallback.

import { ReactNode } from "react";

interface UserDisplayProps {
	userId: string;
	fallback: ReactNode;
}

export default function UserDisplay({ fallback }: UserDisplayProps) {
	return <>{fallback}</>;
}
