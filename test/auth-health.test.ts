import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
	clearAntigravityCredentials,
	hasAntigravityAuth,
	inspectAntigravityAuth,
	removeConversation,
	resolveAntigravityAcpDirectory,
} from "../src/acp/antigravity.js";

const roots: string[] = [];
afterEach(() => {
	for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function root(): string {
	const value = fs.mkdtempSync(path.join(os.tmpdir(), "antigravity-auth-"));
	roots.push(value);
	return value;
}

describe("Antigravity auth health", () => {
	it("does not mistake settings alone for completed authentication", () => {
		const directory = root();
		fs.writeFileSync(path.join(directory, "settings.json"), '{"auth":{"type":"oauth-personal"}}');
		expect(inspectAntigravityAuth(directory).status).toBe("configured-not-authenticated");
	});

	it("recognizes a structurally refreshable token and clears it", () => {
		const directory = root();
		fs.writeFileSync(path.join(directory, "settings.json"), '{"auth":{"type":"oauth-personal"}}');
		fs.writeFileSync(path.join(directory, "acp_token.json"), '{"refresh_token":"secret"}');
		expect(inspectAntigravityAuth(directory).status).toBe("oauth-refreshable");
		clearAntigravityCredentials(directory);
		expect(inspectAntigravityAuth(directory).status).toBe("missing");
	});

	it("reports corrupt token files", () => {
		const directory = root();
		fs.writeFileSync(path.join(directory, "acp_token.json"), "not-json");
		expect(inspectAntigravityAuth(directory).status).toBe("corrupt");
	});

	it("follows an explicit GEMINI_HOME to the relocated token", () => {
		const home = root();
		const acp = path.join(home, "antigravity-acp");
		fs.mkdirSync(acp, { recursive: true });
		fs.writeFileSync(path.join(acp, "acp_token.json"), '{"refresh_token":"secret"}');
		const previous = process.env.GEMINI_HOME;
		process.env.GEMINI_HOME = home;
		try {
			expect(resolveAntigravityAcpDirectory()).toBe(acp);
			expect(inspectAntigravityAuth().status).toBe("oauth-refreshable");
		} finally {
			if (previous === undefined) delete process.env.GEMINI_HOME;
			else process.env.GEMINI_HOME = previous;
		}
	});

	it("ignores an empty GEMINI_HOME and keeps the default home", () => {
		const previous = process.env.GEMINI_HOME;
		process.env.GEMINI_HOME = "  ";
		try {
			expect(resolveAntigravityAcpDirectory()).toBe(
				path.join(os.homedir(), ".gemini", "antigravity-acp"),
			);
		} finally {
			if (previous === undefined) delete process.env.GEMINI_HOME;
			else process.env.GEMINI_HOME = previous;
		}
	});

	it("resolves the store from the environment it is given", () => {
		expect(resolveAntigravityAcpDirectory({ HOME: "/child/home" })).toBe(
			path.join("/child/home", ".gemini", "antigravity-acp"),
		);
		expect(resolveAntigravityAcpDirectory({ HOME: "/child/home", GEMINI_HOME: "/child/workspace" })).toBe(
			path.join("/child/workspace", "antigravity-acp"),
		);
	});

	it("reads the API key from the inspected environment only", () => {
		const directory = root();
		fs.writeFileSync(path.join(directory, "acp_token.json"), '{"refresh_token":"secret"}');
		expect(inspectAntigravityAuth(directory, { GEMINI_API_KEY: "child-key" }).status).toBe("api-key-env");
		expect(inspectAntigravityAuth(directory, {}).status).toBe("oauth-refreshable");
	});
});

describe("hasAntigravityAuth", () => {
	/** Points the inspected store at a directory without any credential file. */
	function withoutTokenFile<T>(run: () => T): T {
		const previousHome = process.env.GEMINI_HOME;
		const previousKey = process.env.GEMINI_API_KEY;
		const previousForceFile = process.env.AGY_ACP_FORCE_FILE_STORAGE;
		process.env.GEMINI_HOME = root();
		delete process.env.GEMINI_API_KEY;
		delete process.env.AGY_ACP_FORCE_FILE_STORAGE;
		try {
			return run();
		} finally {
			if (previousHome === undefined) delete process.env.GEMINI_HOME;
			else process.env.GEMINI_HOME = previousHome;
			if (previousKey === undefined) delete process.env.GEMINI_API_KEY;
			else process.env.GEMINI_API_KEY = previousKey;
			if (previousForceFile === undefined) delete process.env.AGY_ACP_FORCE_FILE_STORAGE;
			else process.env.AGY_ACP_FORCE_FILE_STORAGE = previousForceFile;
		}
	}

	it("accepts a macOS keychain credential without an acp_token.json mirror", () => {
		expect(
			withoutTokenFile(() => hasAntigravityAuth({ platform: "darwin", keychainEntry: () => true })),
		).toBe(true);
	});

	it.each(["1", "true", "TRUE", "yes", "YES"])("ignores keychain credentials when file storage is forced with %s", (value) => {
		withoutTokenFile(() => {
			process.env.AGY_ACP_FORCE_FILE_STORAGE = value;
			let probes = 0;
			expect(hasAntigravityAuth({ platform: "darwin", keychainEntry: () => { probes++; return true; } })).toBe(false);
			expect(probes).toBe(0);
		});
	});

	it.each(["0", "false", "no"])("retains keychain auth when the override is %s", (value) => {
		withoutTokenFile(() => {
			process.env.AGY_ACP_FORCE_FILE_STORAGE = value;
			expect(hasAntigravityAuth({ platform: "darwin", keychainEntry: () => true })).toBe(true);
		});
	});

	it("still accepts a refreshable token file when file storage is forced", () => {
		withoutTokenFile(() => {
			process.env.AGY_ACP_FORCE_FILE_STORAGE = "1";
			fs.mkdirSync(resolveAntigravityAcpDirectory(), { recursive: true });
			fs.writeFileSync(path.join(resolveAntigravityAcpDirectory(), "acp_token.json"), '{"refresh_token":"secret"}');
			expect(hasAntigravityAuth({ platform: "darwin", keychainEntry: () => false })).toBe(true);
		});
	});

	it("reports no credential when neither the keychain nor a token file holds one", () => {
		expect(
			withoutTokenFile(() => hasAntigravityAuth({ platform: "darwin", keychainEntry: () => false })),
		).toBe(false);
	});

	it("ignores the macOS keychain on other platforms", () => {
		expect(withoutTokenFile(() => hasAntigravityAuth({ platform: "linux", keychainEntry: () => true }))).toBe(
			false,
		);
	});
});

describe("removeConversation", () => {
	const sid = "0f8fad5b-d9cb-469f-a165-70867728950e";
	function conversations(names: string[]) {
		const directory = root();
		const dir = path.join(directory, "conversations");
		fs.mkdirSync(dir);
		for (const name of names) fs.writeFileSync(path.join(dir, name), "");
		return { directory, files: () => fs.readdirSync(dir).sort() };
	}

	it("removes exactly the four files of a UUID session", () => {
		const store = conversations([".db", ".db-shm", ".db-wal", ".meta", "-other.db"].map((suffix) => sid + suffix));
		removeConversation(sid, store.directory);
		expect(store.files()).toEqual([`${sid}-other.db`]);
	});

	it.each(["../x", "", `${sid.toUpperCase()}/x`, `../${sid}`])("ignores a session id that is not a UUID: %j", (id) => {
		const store = conversations([`${sid}.db`, "x.db"]);
		removeConversation(id, store.directory);
		expect(store.files()).toEqual([`${sid}.db`, "x.db"]);
	});

	it("skips a session path that is a directory without throwing", () => {
		const store = conversations([`${sid}.meta`]);
		fs.mkdirSync(path.join(store.directory, "conversations", `${sid}.db`));
		expect(() => removeConversation(sid, store.directory)).not.toThrow();
		expect(store.files()).toEqual([`${sid}.db`]);
	});
});
