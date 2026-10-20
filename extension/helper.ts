import { execFile, spawn } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const helperPath = process.env.PI_CREDENTIALS_HELPER || fileURLToPath(new URL("../bin/pi-credentials-helper", import.meta.url));
export const packageRoot = fileURLToPath(new URL("..", import.meta.url));
const buildVariables = ["PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "DEVELOPER_DIR", "PI_CREDENTIALS_SIGNING_IDENTITY"];

export function isHelperMissing(): boolean {
	return !process.env.PI_CREDENTIALS_HELPER && !existsSync(helperPath);
}

function git(args: string[]): Promise<string> {
	return new Promise((resolve, reject) => {
		execFile("git", ["-C", packageRoot, ...args], (error, stdout) => {
			if (error) return reject(new HelperError("helper-build-refused", `Could not check the package with Git: ${error.message}`));
			resolve(stdout.trim());
		});
	});
}

export async function uncommittedChanges(): Promise<string> {
	const top = await git(["rev-parse", "--show-toplevel"]);
	if (realpathSync(top) !== realpathSync(packageRoot)) return `The package is not its own Git checkout (${top}).`;
	return git(["status", "--porcelain", "--untracked-files=all"]);
}

export function buildHelper(): Promise<void> {
	const env = Object.fromEntries(buildVariables.flatMap((name) => process.env[name] ? [[name, process.env[name]]] : []));
	return new Promise((resolve, reject) => {
		const child = spawn("/bin/zsh", ["scripts/build.zsh"], { cwd: packageRoot, env, detached: true, stdio: ["ignore", "ignore", "pipe"] });
		let stderr = "";
		let isTimedOut = false;
		child.stderr.setEncoding("utf8");
		child.stderr.on("data", (chunk: string) => { stderr = (stderr + chunk).slice(-4000); });
		const timer = setTimeout(() => {
			isTimedOut = true;
			try { if (child.pid) process.kill(-child.pid, "SIGKILL"); } catch {}
		}, 600_000);
		child.on("error", (error) => { clearTimeout(timer); reject(new HelperError("helper-build-failed", `Could not start the helper build: ${error.message}`)); });
		child.on("close", (status) => {
			clearTimeout(timer);
			if (isTimedOut) return reject(new HelperError("helper-build-failed", "The helper build timed out after 10 minutes."));
			if (status !== 0 || isHelperMissing()) return reject(new HelperError("helper-build-failed", `The helper build failed: ${stderr.trim().split("\n").slice(-3).join(" ")}`));
			resolve();
		});
	});
}

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
	const known = report.leaks.length;
	const unknown = report.unknown.length;
	if (!known && !unknown) return undefined;
	return [
		`⚠ ${known} Known and ${unknown} Unknown credentials leaked in chat history.`,
		...(known ? ["  Known:", ...report.leaks.map((leak) => `  - ${leak.name}`)] : []),
		"",
		"  register credentials with `/cred register` or `/cred add`",
		"  use `/cred scrub` to clean the chat history of credentials",
		"  use `/cred edit <name> value`, `/cred rotated`, or `/cred rotated all` to start with a clean record.",
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
