import path from "node:path";

import { inspectAntigravityAuth, resolveAntigravityAcpDirectory } from "./antigravity.js";
import {
	defaultKeychainLookup,
	KEYCHAIN_ACCOUNT,
	KEYCHAIN_SERVICE,
	type KeychainEntryProbe,
} from "./keychain.js";

export { KEYCHAIN_ACCOUNT, KEYCHAIN_SERVICE };

/** Selects the Antigravity ACP server's secure-file credential backend
 * (`credential_store.py`: `AGY_ACP_FORCE_FILE_STORAGE`). */
export const FORCE_FILE_STORAGE_ENV = "AGY_ACP_FORCE_FILE_STORAGE";


export type CredentialStorageReason =
	| "explicit-override"
	| "not-darwin"
	| "no-refreshable-token-file"
	| "keychain-entry-present"
	| "missing-keychain-entry";

export interface CredentialStorageDecision {
	/** Child environment entries to apply; empty when the server default is safe. */
	env: Record<string, string>;
	reason: CredentialStorageReason;
}

export interface CredentialStorageOptions {
	env?: NodeJS.ProcessEnv;
	platform?: NodeJS.Platform;
	tokenPath?: string;
	/** Injectable keychain probe for tests; returns whether the entry exists. */
	keychainEntry?: KeychainEntryProbe;
}


/** The server prefers the login keychain on macOS and falls back to the secure
 * file only when that keychain is unusable. A plaintext token file that the
 * keychain does not mirror is therefore invisible to the server: every new
 * server process reports "Credentials missing or invalid", runs interactive
 * Google consent, and can exceed the session-setup deadline. Pin the server to
 * the backend this provider inspects only in that specific mismatch.
 *
 * `options.env` is the environment of the child the decision applies to, which
 * can differ from this process's; the token file and API key are read from it. */
export function resolveCredentialStorageDecision(
	options: CredentialStorageOptions = {},
): CredentialStorageDecision {
	const env = options.env ?? process.env;
	if (env[FORCE_FILE_STORAGE_ENV]?.trim()) return { env: {}, reason: "explicit-override" };

	const platform = options.platform ?? process.platform;
	if (platform !== "darwin") return { env: {}, reason: "not-darwin" };

	const tokenPath = options.tokenPath ?? path.join(resolveAntigravityAcpDirectory(env), "acp_token.json");
	if (inspectAntigravityAuth(path.dirname(tokenPath), env).status !== "oauth-refreshable") {
		return { env: {}, reason: "no-refreshable-token-file" };
	}

	const lookup = options.keychainEntry ?? defaultKeychainLookup;
	if (lookup(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)) return { env: {}, reason: "keychain-entry-present" };

	return {
		env: { [FORCE_FILE_STORAGE_ENV]: "1" },
		reason: "missing-keychain-entry",
	};
}

/** Applies the decision without mutating `baseEnv`, mirroring the other
 * child-only environment adapters. `baseEnv` is the environment the child
 * receives, so the decision inspects that same environment. */
export function applyCredentialStorageEnvironment(
	baseEnv: NodeJS.ProcessEnv = process.env,
	options: Omit<CredentialStorageOptions, "env"> = {},
): NodeJS.ProcessEnv {
	const decision = resolveCredentialStorageDecision({ ...options, env: baseEnv });
	return { ...baseEnv, ...decision.env };
}

/** Describes the backend the next child process is expected to use, for
 * `doctor`/`status` diagnostics. This is a preflight selection inferred from
 * the inspected store, not the backend of a running process: the server's own
 * functional keychain probe can still fall back to the file store. */
export function describeCredentialStorage(options: CredentialStorageOptions = {}): string {
	const decision = resolveCredentialStorageDecision(options);
	switch (decision.reason) {
		case "missing-keychain-entry":
			return `secure file (expected: keychain entry ${KEYCHAIN_SERVICE}/${KEYCHAIN_ACCOUNT} is absent, so spawned server processes are pinned with ${FORCE_FILE_STORAGE_ENV}=1)`;
		case "keychain-entry-present":
			return `macOS keychain (expected: keychain entry ${KEYCHAIN_SERVICE}/${KEYCHAIN_ACCOUNT} is present)`;
		case "explicit-override":
			return `${FORCE_FILE_STORAGE_ENV} set by the user`;
		case "no-refreshable-token-file":
			return "server default (expected: no refreshable token file to reuse)";
		default:
			return "server default (secure file)";
	}
}
