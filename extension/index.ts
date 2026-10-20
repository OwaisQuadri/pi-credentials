import { DynamicBorder, getAgentDir, type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Type } from "@earendil-works/pi-ai";
import { Container, Text } from "@earendil-works/pi-tui";
import { callHelper, describeLeaks, describeListing, buildHelper, HelperError, isHelperMissing, packageRoot, uncommittedChanges, kinds, type Catalog, type Kind, type LeakReport } from "./helper.ts";

const subcommands: Record<string, string> = {
	list: "Show registered credentials and where agents may use them",
	add: "Store a new credential value",
	register: "Take over an existing Keychain item",
	edit: "Change a credential's value, description, kind, hosts, apps, rotation link, or environment variable",
	grant: "Let agents use a credential globally or in a project group",
	revoke: "Remove a grant",
	group: "Set or remove a project group's Git remote patterns",
	delete: "Unregister a credential, optionally deleting its Keychain item",
	env: "Write a .env file with the credentials granted to this project",
	scan: "Scan all saved sessions for leaked credentials",
	rotated: "Clear leak warnings: a credential, a key format, a fingerprint, or all",
	scrub: "Rewrite leaked values in saved sessions to [cred-scrubbed:name] markers",
};

interface EnvResult {
	path: string;
	variables: string[];
	unavailable: string[];
	skipped: string[];
}

function describeEnv(result: EnvResult): string {
	return [
		`Wrote ${result.path} with ${result.variables.join(", ")}.`,
		result.unavailable.length ? `Could not read: ${result.unavailable.join(", ")}.` : "",
		result.skipped.length ? `Skipped (under 8 characters): ${result.skipped.join(", ")}.` : "",
	].filter(Boolean).join(" ");
}

function sessionDirectory(ctx: ExtensionContext): { sessionDir?: string } {
	const directory = ctx.sessionManager.getSessionDir();
	return directory ? { sessionDir: resolve(directory) } : {};
}

function sessionFile(ctx: ExtensionContext): string | undefined {
	const file = ctx.sessionManager.getSessionFile();
	return file ? resolve(file) : undefined;
}

let currentRun = "";

let leakReport: LeakReport = { leaks: [], unknown: [], scanned: 0 };

function setLeakReport(report: LeakReport) {
	leakReport = report;
}

interface ProcessResult {
	status: number;
	stdout: string;
	stderr: string;
	isTruncated: boolean;
	isTimedOut: boolean;
}

const templateSuffixes = [".example", ".sample", ".template", ".dist"];

function realPath(path: string): string {
	try { return realpathSync.native(path); }
	catch { return path; }
}

const unicodeSpaces = /[\u00A0\u2000-\u200A\u202F\u205F\u3000]/g;

export function resolvePiPath(input: string, cwd: string): string | undefined {
	let text = input.replace(unicodeSpaces, " ");
	if (text.startsWith("@")) text = text.slice(1);
	if (text === "~") text = homedir();
	else if (text.startsWith("~/")) text = join(homedir(), text.slice(2));
	if (/^file:\/\//.test(text)) {
		try { text = fileURLToPath(text); }
		catch { return undefined; }
	}
	return isAbsolute(text) ? resolve(text) : resolve(cwd, text);
}

function isProtectedFile(input: string, cwd: string, agent: string): boolean {
	const resolved = resolvePiPath(input, cwd);
	if (resolved === undefined) return true;
	const full = realPath(resolved).toLowerCase();
	const base = basename(full);
	if (base === ".env" || (base.startsWith(".env.") && !templateSuffixes.some((suffix) => base.endsWith(suffix)))) return true;
	return ["auth.json", "mcp-auth.json"].some((name) => full === join(agent, name));
}

export function isProtectedPath(input: string, cwd: string): boolean {
	const agent = agentDirectory();
	return [input, input.trim(), input.trim().replace(/^file:\/\//i, "file://")].some((form) => isProtectedFile(form, cwd, agent));
}

function agentDirectory(): string {
	return realPath(getAgentDir()).toLowerCase();
}

function ripgrepPath(): string {
	const bundled = join(getAgentDir(), "bin", "rg");
	return existsSync(bundled) ? bundled : "rg";
}

function isInside(file: string, root: string): boolean {
	return file === root || file.startsWith(root.endsWith("/") ? root : `${root}/`);
}

const grepProtectedMessage = "pi-credentials refused this grep: it would search a .env file or a Pi auth file. Narrow the path or glob.";

export function grepRefusal(path: string | undefined, glob: string | undefined, cwd: string, timeoutMs = 10_000): Promise<string | undefined> {
	const root = resolvePiPath(path ?? ".", cwd);
	if (root === undefined) return Promise.resolve("pi-credentials could not read this path.");
	if (path !== undefined && isProtectedPath(path, cwd)) return Promise.resolve(grepProtectedMessage);
	const agent = agentDirectory();
	const args = ["--files", "--hidden", "--null", "--color=never", "--path-separator", "/", ...(glob === undefined ? [] : ["--glob", glob]), "--", root];
	return new Promise((done) => {
		let isSettled = false;
		let pending = "";
		const finish = (reason: string | undefined) => {
			if (isSettled) return;
			isSettled = true;
			clearTimeout(timer);
			child.kill("SIGKILL");
			done(reason);
		};
		const child = spawn(ripgrepPath(), args, { stdio: ["ignore", "pipe", "ignore"] });
		const timer = setTimeout(() => finish("pi-credentials could not list the files that this grep would search within 10 seconds. Narrow the path or glob."), timeoutMs);
		child.stdout.setEncoding("utf8");
		child.stdout.on("data", (chunk: string) => {
			const parts = (pending + chunk).split("\0");
			pending = parts.pop() ?? "";
			if (parts.some((file) => !isInside(file, root) || isProtectedFile(file, cwd, agent))) finish(grepProtectedMessage);
		});
		child.on("error", () => finish("pi-credentials could not run ripgrep to check this grep."));
		child.on("close", (code) => {
			if (pending && (!isInside(pending, root) || isProtectedFile(pending, cwd, agent))) finish(grepProtectedMessage);
			else if (code === 0 || code === 1 || (code === 2 && existsSync(root))) finish(undefined);
			else finish("ripgrep could not list this path. It may be missing or unreadable.");
		});
	});
}

interface HTTPResponse {
	status: number;
	contentType?: string;
	body?: string;
	outputFile?: string;
	byteCount?: number;
	isTruncated: boolean;
	redacted: string[];
	unavailable: string[];
}

let cache: Catalog = { credentials: [], groups: {}, projectGroups: [] };
const active = new Map<string, number>();

function showActive(ctx: ExtensionContext) {
	ctx.ui.setStatus("pi-credentials", active.size ? `🔑 ${[...active.keys()].join(", ")}` : undefined);
}

async function withActive<T>(name: string, ctx: ExtensionContext, run: () => Promise<T>): Promise<T> {
	active.set(name, (active.get(name) ?? 0) + 1);
	showActive(ctx);
	try { return await run(); }
	finally {
		const remaining = (active.get(name) ?? 1) - 1;
		if (remaining > 0) active.set(name, remaining);
		else active.delete(name);
		showActive(ctx);
	}
}

function describeProcess(result: ProcessResult): string {
	const stopNote = result.status === -1 ? "Could not stop the command. It may still be running, as root for cred_sudo." : result.isTimedOut ? "Timed out and stopped." : "";
	const notes = [stopNote, result.isTruncated ? "Output truncated at 1 MB." : ""].filter(Boolean);
	return [`Exit status ${result.status}`, ...notes, result.stdout && `stdout:\n${result.stdout}`, result.stderr && `stderr:\n${result.stderr}`].filter(Boolean).join("\n");
}

async function stripCredentialVariables(): Promise<string[]> {
	const names = Object.keys(process.env).filter((name) => (process.env[name]?.length ?? 0) >= 8);
	if (!names.length) return [];
	const separator = `\u0000${randomUUID()}\u0000`;
	const result = await callHelper<{ text: string; redacted: string[] }>("redact", { text: names.map((name) => process.env[name]).join(separator) }, AbortSignal.timeout(10_000));
	if (!result.redacted.length) return [];
	const values = result.text.split(separator);
	if (values.length !== names.length) return [];
	const stripped = names.filter((name, index) => values[index] !== process.env[name]);
	for (const name of stripped) delete process.env[name];
	return stripped;
}

async function refresh(cwd: string): Promise<Catalog> {
	cache = await callHelper<Catalog>("list", { cwd });
	return cache;
}

function isFuzzyMatch(query: string, text: string): boolean {
	let index = 0;
	for (const character of text.toLowerCase()) if (character === query[index]) index += 1;
	return index === query.length;
}

function completions(argumentText: string, catalog: Catalog): { value: string; label: string; description?: string }[] | null {
	const parts = argumentText.split(/\s+/);
	const current = (parts.pop() ?? "").toLowerCase();
	const head = parts.length ? `${parts.join(" ")} ` : "";
	const options: { label: string; description?: string }[] = [];
	const [subcommand, name] = parts;
	if (parts.length === 0) {
		for (const [label, description] of Object.entries(subcommands)) options.push({ label, description });
	} else if (parts.length === 1 && !["list", "env", "scan", "scrub"].includes(subcommand)) {
		if (subcommand === "rotated") {
			options.push({ label: "all", description: "clear every leak warning" });
			for (const leak of leakReport.leaks) options.push({ label: leak.name, description: `${leak.sessions} sessions, last ${leak.last}` });
			for (const prefix of new Set(leakReport.unknown.map((leak) => leak.prefix))) options.push({ label: prefix, description: `all unregistered ${prefix}… keys` });
			for (const leak of leakReport.unknown) options.push({ label: leak.fingerprint, description: `unregistered ${leak.prefix}…, ${leak.sessions} sessions` });
		} else if (subcommand === "group") {
			for (const [label, patterns] of Object.entries(catalog.groups)) options.push({ label, description: patterns.join(", ") });
		} else if (subcommand !== "add" && subcommand !== "register") {
			for (const listing of catalog.credentials) options.push({ label: listing.name, description: describeListing(listing) });
		}
	} else if (parts.length === 2 && (subcommand === "grant" || subcommand === "revoke")) {
		const listing = catalog.credentials.find((item) => item.name === name);
		const scopes = subcommand === "revoke" ? listing?.grants ?? [] : ["global", ...Object.keys(catalog.groups)];
		for (const scope of scopes) {
			options.push({ label: scope, description: scope === "global" ? "Every project" : (catalog.groups[scope] ?? []).join(", ") });
		}
	} else if (parts.length === 2 && subcommand === "add" || parts.length === 3 && subcommand === "register") {
		for (const kind of kinds) options.push({ label: kind });
	}
	const isPrefix = (label: string) => label.toLowerCase().startsWith(current);
	const items = options.filter((option) => isFuzzyMatch(current, option.label))
		.sort((first, second) => Number(isPrefix(second.label)) - Number(isPrefix(first.label)))
		.map((option) => ({ value: `${head}${option.label} `, ...option }));
	return items.length ? items : null;
}

function parseKind(text: string | undefined): Kind | undefined {
	if (text === undefined) return undefined;
	if (!kinds.includes(text as Kind)) throw new HelperError("invalid-kind", `Kind must be one of: ${kinds.join(", ")}.`);
	return text as Kind;
}

async function askMetadata(ctx: ExtensionContext, kind?: Kind) {
	const selectedKind = kind ?? await ctx.ui.select("Kind", kinds) as Kind | undefined;
	if (!selectedKind) return undefined;
	const description = await ctx.ui.input("Description", "What is this credential for?");
	if (!description?.trim()) return undefined;
	let hosts: string[] = [];
	let apps: string[] = [];
	if (selectedKind === "api-key") {
		const text = await ctx.ui.input("Allowed hosts", "api.example.com, *.example.org (empty means any host)");
		if (text === undefined) return undefined;
		hosts = text.split(",").map((host) => host.trim()).filter(Boolean);
	} else if (selectedKind === "password" || selectedKind === "passcode") {
		const text = await ctx.ui.input("Apps that may receive it by typing", "Bundle identifiers, such as com.apple.ScreenContinuity (empty means no typing)");
		if (text === undefined) return undefined;
		apps = text.split(",").map((app) => app.trim()).filter(Boolean);
	}
	return { kind: selectedKind, description: description.trim(), hosts, apps };
}

async function runCommand(argumentText: string, ctx: ExtensionContext, pi: ExtensionAPI): Promise<string | undefined> {
	const [subcommand = "list", name, ...rest] = argumentText.trim().split(/\s+/).filter(Boolean);
	const cwd = ctx.cwd;
	const catalog = await refresh(cwd);
	const requireName = () => {
		if (!name) throw new HelperError("missing-name", `Usage: /cred ${subcommand} <name>`);
		return name;
	};
	switch (subcommand) {
		case "list": {
			if (!catalog.credentials.length) return "No credentials are registered. Use /cred add or /cred register.";
			const lines = catalog.credentials.map((listing) => `${listing.isGranted ? "●" : "○"} ${listing.name} · ${describeListing(listing)}`);
			const choice = await ctx.ui.select(`Credentials · ● usable in this project${catalog.projectGroups.length ? ` (${catalog.projectGroups.join(", ")})` : ""}`, lines);
			if (!choice) return undefined;
			const listing = catalog.credentials[lines.indexOf(choice)];
			return [`${listing.name}: ${listing.description}`, `Kind: ${listing.kind}`, `Last use: ${listing.lastUse ?? "never"}`, `Hosts: ${listing.hosts.join(", ") || "any"}`, `Apps: ${listing.apps.join(", ") || "none (never typed)"}`, `Grants: ${listing.grants.join(", ") || "none"}`, listing.rotation ? `Rotate at: ${listing.rotation}` : ""].filter(Boolean).join("\n");
		}
		case "add": {
			requireName();
			const kind = parseKind(rest[0]);
			if (catalog.credentials.some((item) => item.name === name)) throw new HelperError("exists", `${name} is already registered. Use /cred edit.`);
			const metadata = await askMetadata(ctx, kind);
			if (!metadata) return undefined;
			const value = await ctx.ui.input(`Value for ${name}`, "Paste the secret");
			if (!value) return undefined;
			await callHelper("add", { name, value, ...metadata });
			return `Stored ${name}. Grant it with /cred grant ${name} <scope>.`;
		}
		case "register": {
			requireName();
			const service = rest[0];
			if (!service) throw new HelperError("missing-service", "Usage: /cred register <name> <keychain service> [kind]");
			const kind = parseKind(rest[1]);
			if (catalog.credentials.some((item) => item.name === name)) throw new HelperError("exists", `${name} is already registered. Use /cred edit.`);
			const metadata = await askMetadata(ctx, kind);
			if (!metadata) return undefined;
			await callHelper("register", { name, service, ...metadata });
			return `Registered ${name}. Other programs now get a macOS dialog before reading it.`;
		}
		case "edit": {
			const listing = catalog.credentials.find((item) => item.name === requireName());
			if (!listing) throw new HelperError("unknown-credential", `No credential is named ${name}.`);
			const fields = ["value", "description", "kind", "hosts", "apps", "rotation link", "environment variable"];
			const requested = rest.join(" ");
			const field = fields.includes(requested) ? requested : await ctx.ui.select(`Edit ${name}`, fields);
			if (!field) return undefined;
			const change: Record<string, unknown> = {};
			if (field === "value") {
				const value = await ctx.ui.input(`New value for ${name}`, "Paste the new secret. This counts as a rotation.");
				if (!value) return undefined;
				change.value = value;
			} else if (field === "kind") {
				const kind = await ctx.ui.select("Kind", kinds);
				if (!kind) return undefined;
				change.kind = kind;
			} else {
				const current = field === "hosts" ? listing.hosts.join(", ") : field === "apps" ? listing.apps.join(", ") : field === "description" ? listing.description : field === "environment variable" ? listing.env : listing.rotation ?? "";
				const text = await ctx.ui.input(`New ${field} (now: ${current || "none"})`, field === "hosts" ? "comma separated, empty means any host" : field === "apps" ? "comma separated bundle identifiers, empty means never typed" : "");
				if (text === undefined || (field === "description" && !text.trim())) return undefined;
				const list = text.split(",").map((item) => item.trim()).filter(Boolean);
				if (field === "hosts") change.hosts = list;
				else if (field === "apps") change.apps = list;
				else if (field === "description") change.description = text.trim();
				else if (field === "environment variable") change.env = text.trim();
				else change.rotation = text.trim();
			}
			const isLeakedBefore = leakReport.leaks.some((leak) => leak.name === name);
			const result = await callHelper<{ report: LeakReport }>("edit", { name, ...change });
			setLeakReport(result.report);
			if (field === "value" && isLeakedBefore && !result.report.leaks.some((leak) => leak.name === name)) return `Edited ${name}. Its leak warnings are resolved.`;
			return `Edited ${name}.`;
		}
		case "grant":
		case "revoke": {
			const scope = rest[0];
			if (!scope) throw new HelperError("missing-scope", `Usage: /cred ${subcommand} <name> <global|group>`);
			await callHelper(subcommand, { name: requireName(), scope });
			return subcommand === "grant" ? `Agents may use ${name} in ${scope}.` : `Revoked ${name} from ${scope}.`;
		}
		case "group": {
			const patterns = rest;
			if (!patterns.length && !(await ctx.ui.confirm(`Remove project group ${requireName()}?`, "Its grants are removed too."))) return undefined;
			await callHelper("group", { name: requireName(), patterns });
			return patterns.length ? `Group ${name}: ${patterns.join(", ")}` : `Removed group ${name}.`;
		}
		case "delete": {
			const choice = await ctx.ui.select(`Delete ${requireName()}`, ["Unregister only; keep the Keychain item", "Unregister and delete the Keychain item"]);
			if (!choice) return undefined;
			await callHelper("delete", { name, isValueDeleted: choice.startsWith("Unregister and") });
			return `Deleted ${name}.`;
		}
		case "scan": {
			ctx.ui.notify("Scanning saved sessions. This can take a few minutes.", "info");
			const report = await callHelper<LeakReport>("scan", { isFull: true, ...sessionDirectory(ctx) });
			setLeakReport(report);
			const lines = describeLeaks(report);
			if (lines && ctx.hasUI) pi.appendEntry("pi-credentials-leaks", { lines, run: currentRun });
			return `Scanned ${report.scanned} files. ${report.leaks.length + report.unknown.length ? "See the warning above." : "No leaked credentials found."}`;
		}
		case "rotated": {
			const choices = ["all", ...leakReport.leaks.map((leak) => leak.name), ...new Set(leakReport.unknown.map((leak) => leak.prefix))];
			const target = name ?? await ctx.ui.select("Clear leak warnings for", choices);
			if (!target) return undefined;
			setLeakReport(await callHelper<LeakReport>("rotated", { name: target }));
			return target === "all" ? "Cleared every leak warning." : `Cleared the leak warnings of ${target}.`;
		}
		case "scrub": {
			if (!(await ctx.ui.confirm("Rewrite leaked values in saved sessions?", "Matches become [cred-scrubbed:name] or [cred:unknown-…] markers. Sessions changed in the last 10 minutes are skipped."))) return undefined;
			const result = await callHelper<{ rewritten: number; skipped: number; report: LeakReport }>("scrub", { exclude: sessionFile(ctx) });
			setLeakReport(result.report);
			return `Rewrote ${result.rewritten} files.${result.skipped ? ` Skipped ${result.skipped} recently active files; run /cred scrub again later.` : ""}`;
		}
		case "env": {
			const result = await callHelper<EnvResult>("env", { cwd, path: name, session: ctx.sessionManager.getSessionId() });
			return describeEnv(result);
		}
		default:
			throw new HelperError("unknown-subcommand", `Unknown subcommand ${subcommand}. Use ${Object.keys(subcommands).join(", ")}.`);
	}
}

async function offerGrant(name: string, ctx: ExtensionContext, usableKinds: Kind[], signal?: AbortSignal): Promise<boolean> {
	if (!ctx.hasUI) return false;
	const catalog = await refresh(ctx.cwd);
	const kind = catalog.credentials.find((item) => item.name === name)?.kind;
	if (!kind || !usableKinds.includes(kind)) return false;
	const scopes = [...catalog.projectGroups, "global"];
	const choice = await ctx.ui.select(`An agent wants to use ${name}. Grant it?`, [...scopes.map((scope) => `Grant to ${scope}`), "Do not grant"], { signal });
	if (!choice || choice === "Do not grant") return false;
	await callHelper("grant", { name, scope: choice.slice("Grant to ".length) });
	await refresh(ctx.cwd);
	return true;
}

export default function piCredentials(pi: ExtensionAPI) {
	currentRun = randomUUID();
	pi.registerEntryRenderer<{ lines: string[]; run: string }>("pi-credentials-leaks", (entry, _options, theme) => {
		const [header, ...rest] = entry.data?.lines ?? [];
		if (!header || entry.data?.run !== currentRun) return undefined;
		const box = new Container();
		box.addChild(new DynamicBorder((text) => theme.fg("warning", text)));
		box.addChild(new Text(`${theme.bold(theme.fg("warning", header))}\n${rest.join("\n")}`, 1, 0));
		box.addChild(new DynamicBorder((text) => theme.fg("warning", text)));
		return box;
	});
	pi.on("session_start", async (_event, ctx) => {
		try {
			if (isHelperMissing()) {
				const fix = `Run scripts/build.zsh in ${packageRoot}.`;
				if (!ctx.hasUI) throw new HelperError("helper-unavailable", `The helper is missing. ${fix}`);
				const refusal = await uncommittedChanges().catch((error: Error) => error.message);
				if (refusal) throw new HelperError("helper-build-refused", `The helper is missing and was not built automatically: ${refusal} ${fix}`);
				const isApproved = await ctx.ui.confirm("Build the pi-credentials helper?", `The helper is missing, usually after pi update. This builds and signs it from ${packageRoot}. Pi finishes starting when the build is done.`);
				if (!isApproved) throw new HelperError("helper-unavailable", `The helper is missing. ${fix}`);
				ctx.ui.notify("pi-credentials is building its helper.", "info");
				await buildHelper();
				ctx.ui.notify("pi-credentials built its helper.", "info");
			}
			await refresh(ctx.cwd);
			const stripped = await stripCredentialVariables();
			if (stripped.length) ctx.ui.notify(`pi-credentials removed ${stripped.join(", ")} from this Pi process. Tools now reach those credentials through the broker.`, "info");
			void callHelper<LeakReport>("scan", sessionDirectory(ctx)).then((report) => {
				setLeakReport(report);
				const lines = describeLeaks(report);
				if (lines && ctx.hasUI) pi.appendEntry("pi-credentials-leaks", { lines, run: currentRun });
			}).catch(() => undefined);
		} catch (error) { ctx.ui.notify(`pi-credentials: ${(error as Error).message}`, "warning"); }
	});

	pi.on("tool_call", async (event, ctx) => {
		if (!["read", "edit", "grep"].includes(event.toolName)) return undefined;
		const input = event.input as { path?: unknown; glob?: unknown };
		const path = typeof input.path === "string" ? input.path : undefined;
		const glob = event.toolName === "grep" && typeof input.glob === "string" ? input.glob : undefined;
		if (event.toolName === "grep") {
			const reason = await grepRefusal(path, glob, ctx.cwd);
			return reason === undefined ? undefined : { block: true, reason: `${reason} Use cred_list and the cred tools for credentials.` };
		}
		if (path === undefined || !isProtectedPath(path, ctx.cwd)) return undefined;
		return { block: true, reason: "pi-credentials protects .env and Pi auth files. Use cred_list and the cred tools, or cred_env to write a .env file." };
	});

	async function useCredential<T>(name: string, ctx: ExtensionContext, usableKinds: Kind[], signal: AbortSignal | undefined, run: () => Promise<T>): Promise<T> {
		return withActive(name, ctx, async () => {
			try { return await run(); }
			catch (error) {
				if (!(error instanceof HelperError) || error.code !== "not-granted" || !(await offerGrant(name, ctx, usableKinds, signal))) throw error;
				return run();
			}
		});
	}

	const base = (ctx: ExtensionContext) => ({ cwd: ctx.cwd, session: ctx.sessionManager.getSessionId() });

	pi.registerTool({
		name: "cred_type",
		label: "Type credential",
		description: "Type a registered password or passcode into a running app, such as a login field or iPhone Mirroring. The helper types it; you never see it. With isActivating (default true) the app comes to the front first; set it false to type into the app in the background.",
		parameters: Type.Object({
			name: Type.String({ description: "Registered password or passcode credential." }),
			app: Type.String({ description: "Running app's bundle identifier or name." }),
			isActivating: Type.Optional(Type.Boolean()),
			isReturnPressed: Type.Optional(Type.Boolean({ description: "Press Return after typing." })),
		}, { additionalProperties: false }),
		async execute(_id, input, signal, _update, ctx) {
			const result = await useCredential(input.name, ctx, ["password", "passcode"], signal, () => callHelper<{ typed: string }>("type", { ...base(ctx), ...input }, signal));
			return { content: [{ type: "text", text: `Typed ${input.name} into ${result.typed}.` }], details: result };
		},
	});

	pi.registerTool({
		name: "cred_sudo",
		label: "Run as root",
		description: "Run one command as root with a registered password. The user approves the exact command with Touch ID each time. Needs a user present.",
		parameters: Type.Object({
			name: Type.String({ description: "Registered password credential, such as the Mac login password." }),
			command: Type.Array(Type.String(), { description: "Program and arguments, without sudo. Not run through a shell.", minItems: 1 }),
			timeoutSeconds: Type.Optional(Type.Number({ description: "Default 600, at most 3600." })),
		}, { additionalProperties: false }),
		async execute(_id, input, signal, _update, ctx) {
			if (!ctx.hasUI) throw new Error("No user is present to approve a root command. Record the need and continue with other work.");
			const result = await useCredential(input.name, ctx, ["password"], signal, () => callHelper<ProcessResult>("sudo", { ...base(ctx), name: input.name, arguments: input.command, timeoutSeconds: input.timeoutSeconds }, signal));
			return { content: [{ type: "text", text: describeProcess(result) }], details: { status: result.status }, isError: result.status !== 0 };
		},
	});

	pi.registerTool({
		name: "cred_notarize",
		label: "Notarize",
		description: "Run xcrun notarytool with a registered app-specific password, which the helper supplies on standard input. Pass the notarytool arguments, including --apple-id and --team-id, without --password.",
		parameters: Type.Object({
			name: Type.String({ description: "Registered app-password credential." }),
			arguments: Type.Array(Type.String(), { description: "notarytool subcommand and arguments: submit, info, wait, log, or history.", minItems: 1 }),
		}, { additionalProperties: false }),
		async execute(_id, input, signal, _update, ctx) {
			const result = await useCredential(input.name, ctx, ["app-password"], signal, () => callHelper<ProcessResult>("notarize", { ...base(ctx), ...input }, signal));
			return { content: [{ type: "text", text: describeProcess(result) }], details: { status: result.status }, isError: result.status !== 0 };
		},
	});

	pi.registerTool({
		name: "cred_env",
		label: "Write .env",
		description: "Write a .env file with the api-key and app-password credentials granted to this project, under each credential's variable name from cred_list. Git must ignore the file. You may create it but not read it.",
		parameters: Type.Object({
			path: Type.Optional(Type.String({ description: "File named .env or .env.<suffix>, relative to the project. Default .env." })),
			names: Type.Optional(Type.Array(Type.String(), { description: "Credentials to include. Default: every granted api-key and app-password." })),
		}, { additionalProperties: false }),
		async execute(_id, input, signal, _update, ctx) {
			const result = await callHelper<EnvResult>("env", { ...base(ctx), ...input }, signal);
			const text = describeEnv(result);
			return { content: [{ type: "text", text }], details: result };
		},
	});

	pi.registerCommand("cred", {
		description: "Manage credentials that agents can use without seeing them",
		getArgumentCompletions: (argumentText) => completions(argumentText, cache),
		handler: async (argumentText, ctx) => {
			try {
				const message = await runCommand(argumentText, ctx, pi);
				if (message) ctx.ui.notify(message, "info");
			} catch (error) {
				ctx.ui.notify((error as Error).message, "error");
			} finally {
				await refresh(ctx.cwd).catch(() => undefined);
			}
		},
	});

	pi.registerTool({
		name: "cred_list",
		label: "Credentials",
		description: "List registered credentials: name, kind, purpose, allowed hosts, and whether this project may use each one. Never returns values.",
		parameters: Type.Object({}, { additionalProperties: false }),
		async execute(_id, _input, _signal, _update, ctx) {
			const catalog = await refresh(ctx.cwd);
			const lines = catalog.credentials.map((listing) => `${listing.isGranted ? "usable" : "not granted"} · ${listing.name} · ${describeListing(listing)}`);
			const text = lines.length ? lines.join("\n") : "No credentials are registered.";
			return { content: [{ type: "text", text }], details: catalog };
		},
	});

	pi.registerTool({
		name: "cred_request",
		label: "Credential request",
		description: "Send an https request authenticated with a registered api-key credential. The helper adds the key; you never see it. Check cred_list first.",
		parameters: Type.Object({
			name: Type.String({ description: "Registered credential name." }),
			method: Type.String({ description: "HTTP method, such as GET or POST." }),
			url: Type.String({ description: "Absolute https URL on one of the credential's allowed hosts." }),
			headers: Type.Optional(Type.Record(Type.String(), Type.String())),
			body: Type.Optional(Type.String()),
			authHeader: Type.Optional(Type.String({ description: "Header for the key. Default Authorization." })),
			authPrefix: Type.Optional(Type.String({ description: "Text before the key. Default 'Bearer '. Use '' for raw keys." })),
			outputFile: Type.Optional(Type.String({ description: "Save response bytes to a new file, relative to the project or absolute. At most 100 MiB; existing paths and symlinks are refused. Only metadata returns." })),
		}, { additionalProperties: false }),
		async execute(_id, input, signal, _update, ctx) {
			const { name, ...request } = input;
			const response = await useCredential(name, ctx, ["api-key"], signal, () => callHelper<HTTPResponse>("request", { ...base(ctx), name, request }, signal));
			if (request.outputFile !== undefined) {
				if (response.outputFile === undefined || response.byteCount === undefined) throw new Error("The helper did not confirm a saved file. Rebuild the helper before using outputFile.");
				const { status, contentType, outputFile, byteCount, redacted } = response;
				const text = [`HTTP ${status}${contentType ? ` · ${contentType}` : ""}`, `Saved ${byteCount} bytes to ${outputFile}.`].join("\n");
				return { content: [{ type: "text", text }], details: { status, contentType, outputFile, byteCount, redacted } };
			}
			{
				const notes = [response.isTruncated ? "Body truncated at 1 MB." : "", response.unavailable.length ? `Could not check output for: ${response.unavailable.join(", ")}.` : ""].filter(Boolean);
				const text = [`HTTP ${response.status}${response.contentType ? ` · ${response.contentType}` : ""}`, ...notes, "", response.body].join("\n");
				return { content: [{ type: "text", text }], details: { status: response.status, redacted: response.redacted } };
			}
		},
	});

	pi.registerTool({
		name: "cred_ask",
		label: "Ask for a credential",
		description: "Ask the user to enter a new secret. The value goes straight to Keychain and never returns to you. Returns the stored credential name.",
		parameters: Type.Object({
			name: Type.String({ description: "Name to store it under: letters, digits, '-', '_', '.'" }),
			reason: Type.String({ description: "Why the task needs it, shown to the user." }),
			kind: Type.Union(kinds.map((kind) => Type.Literal(kind))),
			description: Type.String({ description: "What the credential is for, kept in the catalog." }),
			hosts: Type.Optional(Type.Array(Type.String(), { description: "Allowed hosts for an api-key." })),
		}, { additionalProperties: false }),
		async execute(_id, input, signal, _update, ctx) {
			if (!ctx.hasUI) throw new Error("No user is present to enter a credential. Record the need and continue with other work.");
			if (!input.description.trim()) throw new Error("Give a description of what the credential is for.");
			const value = await ctx.ui.input(`${input.reason} · value for ${input.name} (${input.kind})`, "Paste the secret, or press Escape to decline", { signal });
			if (!value) throw new Error("The user declined to enter the credential.");
			await callHelper("add", { name: input.name, value, kind: input.kind, description: input.description.trim(), hosts: input.hosts ?? [] });
			await refresh(ctx.cwd);
			return { content: [{ type: "text", text: `Stored as ${input.name}. It is not granted yet; ask the user to run /cred grant ${input.name} <scope>, or call cred_request and accept the grant prompt.` }], details: { name: input.name } };
		},
	});

	pi.on("tool_result", async (event) => {
		const withheld = (reason: string) => ({ content: [{ type: "text" as const, text: `pi-credentials withheld this output because ${reason}` }], structuredContent: undefined, details: {}, isError: true });
		try {
			const parts = event.content ?? [];
			const texts = parts.filter((part) => part.type === "text").map((part) => part.text);
			const serialize = (value: unknown) => value === undefined ? undefined : JSON.stringify(value);
			const structured = serialize(event.structuredContent);
			const details = serialize(event.details);
			const pieces = [...texts, structured ?? "", details ?? ""];
			let separator = `\u0000${randomUUID()}\u0000`;
			while (pieces.some((piece) => piece.includes(separator))) separator = `\u0000${randomUUID()}\u0000`;
			const result = await callHelper<{ text: string; redacted: string[]; unavailable: string[] }>("redact", { text: pieces.join(separator) }, AbortSignal.timeout(10_000));
			if (!result.redacted.length && !result.unavailable.length) return undefined;
			const redacted = result.text.split(separator);
			if (redacted.length !== pieces.length) return withheld("redaction changed its structure.");
			let index = 0;
			const content = parts.map((part) => part.type === "text" ? { ...part, text: redacted[index++] } : part);
			if (result.unavailable.length) content.push({ type: "text", text: `pi-credentials could not check this output for: ${result.unavailable.join(", ")}.` });
			const parse = (text: string | undefined, original: string | undefined) => {
				if (original === undefined) return undefined;
				try { return JSON.parse(text ?? ""); }
				catch { return undefined; }
			};
			return { content, structuredContent: parse(redacted[index], structured), details: details === undefined ? undefined : parse(redacted[index + 1], details) ?? {} };
		} catch (error) {
			return withheld(`redaction failed: ${error instanceof Error ? error.message : String(error)}`);
		}
	});
}
