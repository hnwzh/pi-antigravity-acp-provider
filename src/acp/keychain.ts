import { execFileSync } from "node:child_process";

/** macOS keychain coordinates of the server's consumer (CCPA) credential:
 * `credential_store.KEYCHAIN_SERVICE` and the consumer `_KEYCHAIN_ACCOUNT`. */
export const KEYCHAIN_SERVICE = "gemini";
export const KEYCHAIN_ACCOUNT = "antigravity-acp";

const SECURITY_CLI = "/usr/bin/security";
const KEYCHAIN_LOOKUP_TIMEOUT_MS = 3_000;

/** Injectable keychain probe; returns whether the entry exists. */
export type KeychainEntryProbe = (service: string, account: string) => boolean;

export function defaultKeychainLookup(service: string, account: string): boolean {
	try {
		execFileSync(SECURITY_CLI, ["find-generic-password", "-s", service, "-a", account], {
			timeout: KEYCHAIN_LOOKUP_TIMEOUT_MS,
			stdio: "ignore",
		});
		return true;
	} catch {
		// Absent, locked, or denied: treat the entry as unavailable.
		return false;
	}
}

/**
 * macOS keeps the server's OAuth credential in the login keychain; the
 * plaintext `acp_token.json` is only a fallback mirror. A keychain-only login
 * is therefore still a usable credential, and callers that gate network model
 * discovery on credential presence must not require the file.
 */
export function keychainCredentialPresent(
	platform: NodeJS.Platform = process.platform,
	probe: KeychainEntryProbe = defaultKeychainLookup,
): boolean {
	return platform === "darwin" && probe(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
}
