import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

export const helperPath = process.env.PI_CREDENTIALS_HELPER ?? fileURLToPath(new URL("../bin/pi-credentials-helper", import.meta.url));

export type Kind = "api-key" | "password" | "app-password" | "passcode";
export const kinds: Kind[] = ["api-key", "password", "app-password", "passcode"];

export interface Listing {
	name: string;
	description: string;
	kind: Kind;
	hosts: string[];
	apps: string[];
	rotation?: string;
	env: string;
	grants: string[];
	isGranted: boolean;
	lastUse?: string;
}

export interface LeakReport {
	leaks: { name: string; rotation?: string; sessions: number; last: string }[];
	unknown: { fingerprint: string; prefix: string; sessions: number; last: string }[];
	scanned: number;
}

export function describeLeaks(report: LeakReport): string[] | undefined {
	const count = report.leaks.length + report.unknown.length;
	if (!count) return undefined;
	const sessions = (value: number) => `${value} session${value === 1 ? "" : "s"}`;
	return [
		`⚠ ${count} credential${count === 1 ? "" : "s"} leaked in chat history. Rotate ${count === 1 ? "it" : "them"}:`,
		...report.leaks.map((leak) => `  ${leak.name}  ${sessions(leak.sessions)}, last ${leak.last} → ${leak.rotation ?? `/cred edit ${leak.name} to add a rotation link`}`),
		...[...new Set(report.unknown.map((leak) => leak.prefix))].map((prefix) => {
			const group = report.unknown.filter((leak) => leak.prefix === prefix);
			const total = group.reduce((sum, leak) => sum + leak.sessions, 0);
			const last = group.map((leak) => leak.last).sort().at(-1);
			return `  ${group.length} unregistered ${prefix}… key${group.length === 1 ? "" : "s"}  ${sessions(total)}, last ${last} → rotate at the provider, then /cred rotated ${prefix}`;
		}),
		"  /cred scrub rewrites them in saved sessions.",
	];
}

export interface Catalog {
	credentials: Listing[];
	groups: Record<string, string[]>;
	projectGroups: string[];
}

export class HelperError extends Error {
	readonly code: string;

	constructor(code: string, message: string) {
		super(message);
		this.code = code;
	}
}

export function callHelper<T>(command: string, input: Record<string, unknown>, signal?: AbortSignal): Promise<T> {
	return new Promise((resolve, reject) => {
		const child = spawn(helperPath, [command], { stdio: ["pipe", "pipe", "ignore"], signal });
		let output = "";
		child.stdout.setEncoding("utf8");
		child.stdout.on("data", (chunk: string) => { output += chunk; });
		child.stdin.on("error", () => undefined);
		child.on("error", (error) => {
			if (error.name === "AbortError") {
				const isTimeout = (signal?.reason as Error | undefined)?.name === "TimeoutError";
				return reject(isTimeout ? new HelperError("timeout", "The helper did not respond in time.") : new HelperError("aborted", "The credential operation was cancelled."));
			}
			reject(new HelperError("helper-unavailable", `pi-credentials helper failed to start (${error.message}). Run scripts/build.zsh in the package.`));
		});
		child.on("close", () => {
			let parsed: { error?: { code: string; message: string } } & T;
			try { parsed = JSON.parse(output); }
			catch { return reject(new HelperError("helper-output", "pi-credentials helper returned invalid output.")); }
			if (parsed.error) return reject(new HelperError(parsed.error.code, parsed.error.message));
			resolve(parsed);
		});
		child.stdin.end(JSON.stringify(input));
	});
}

export function describeListing(listing: Listing): string {
	const hosts = listing.kind === "api-key" ? ` · ${listing.hosts.length ? listing.hosts.join(", ") : "any host"}` : "";
	const scope = listing.grants.length ? listing.grants.join(", ") : "not granted";
	const used = listing.lastUse ? ` · used ${new Date(listing.lastUse).toLocaleDateString("en-CA")}` : "";
	return `${listing.kind}${hosts} · ${scope}${used} · ${listing.description}`;
}
