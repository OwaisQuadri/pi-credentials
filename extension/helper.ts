import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { binaryPath, ensureBuilt, isBuildNeeded, progressBar, refusalReason, type BuildSpec } from "pi-compiled";

export const packageRoot = fileURLToPath(new URL("..", import.meta.url));
export const helperBuild: BuildSpec = {
	packageRoot,
	binary: "bin/pi-credentials-helper",
	buildCommand: ["/bin/zsh", "-f", "scripts/build.zsh"],
	inputs: ["Package*.swift", "helper", "scripts"],
	envAllowlist: ["PI_CREDENTIALS_SIGNING_IDENTITY"],
	overrideEnv: "PI_CREDENTIALS_HELPER",
	isUpstreamRequired: true,
};
export const helperPath = binaryPath(helperBuild);

export async function prepareHelper(ctx: Pick<ExtensionContext, "hasUI" | "ui">, build: BuildSpec = helperBuild): Promise<void> {
	if (build.overrideEnv && process.env[build.overrideEnv]) {
		await ensureBuilt(build);
		return;
	}
	if (!(await isBuildNeeded(build))) return;
	const fix = `Run scripts/build.zsh in ${build.packageRoot}.`;
	const refusal = (await refusalReason(build).catch((error: Error) => error.message))
		|| (existsSync(join(build.packageRoot, ".swiftpm")) ? "remove .swiftpm, because SwiftPM reads its configuration, which Git does not track." : "");
	if (refusal) throw new HelperError("helper-build-refused", `The helper is missing or out of date and was not built automatically: ${refusal} ${fix}`);
	const show = (text?: string) => { try { if (ctx.hasUI) ctx.ui.setWidget("pi-credentials-build", text === undefined ? undefined : [`pi-credentials helper: ${text}`]); } catch {} };
	show("starting the build");
	try {
		await ensureBuilt(build, { onProgress: (progress) => show(progressBar(progress)) });
	} catch (error) {
		show();
		throw error;
	}
	show("built and signed.");
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

export interface Project {
	name: string;
	repositories: string[];
}

export interface Catalog {
	credentials: Listing[];
	groups: Record<string, string[]>;
	projectGroups: string[];
	projects: Record<string, Project>;
	projectIDs: string[];
	repository?: string;
}

export function describeScope(scope: string, catalog: Catalog): string {
	const project = scope.startsWith("project:") ? catalog.projects[scope.slice("project:".length)] : undefined;
	return project ? `${project.name} (${scope})` : scope;
}

export class HelperError extends Error {
	readonly code: string;

	constructor(code: string, message: string) {
		super(message);
		this.code = code;
	}
}

export function parseHelperOutput<T>(output: string): T {
	let parsed: { error?: { code: string; message: string } } & T;
	try { parsed = JSON.parse(output); }
	catch { throw new HelperError("helper-output", "pi-credentials helper returned invalid output."); }
	if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new HelperError("helper-output", "pi-credentials helper returned invalid output.");
	if (parsed.error) {
		if (typeof parsed.error !== "object" || typeof parsed.error.code !== "string" || typeof parsed.error.message !== "string") throw new HelperError("helper-output", "pi-credentials helper returned invalid output.");
		throw new HelperError(parsed.error.code, parsed.error.message);
	}
	return parsed;
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
			try { resolve(parseHelperOutput<T>(output)); }
			catch (error) { reject(error); }
		});
		child.stdin.end(JSON.stringify(input));
	});
}

export function describeListing(listing: Listing, catalog?: Catalog): string {
	const hosts = listing.kind === "api-key" ? ` · ${listing.hosts.length ? listing.hosts.join(", ") : "any host"}` : "";
	const scope = listing.grants.length ? listing.grants.map((grant) => catalog ? describeScope(grant, catalog) : grant).join(", ") : "not granted";
	const used = listing.lastUse ? ` · used ${new Date(listing.lastUse).toLocaleDateString("en-CA")}` : "";
	return `${listing.kind}${hosts} · ${scope}${used} · ${listing.description}`;
}
