import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { randomUUID } from "node:crypto";
import { Type } from "@earendil-works/pi-ai";
import { callHelper, describeListing, HelperError, kinds, type Catalog, type Kind } from "./helper.ts";

const subcommands: Record<string, string> = {
	list: "Show registered credentials and where agents may use them",
	add: "Store a new credential value",
	register: "Take over an existing Keychain item",
	edit: "Change a credential's description, kind, hosts, or apps",
	grant: "Let agents use a credential globally or in a project group",
	revoke: "Remove a grant",
	group: "Set or remove a project group's Git remote patterns",
	delete: "Unregister a credential, optionally deleting its Keychain item",
};

interface HTTPResponse {
	status: number;
	contentType?: string;
	body: string;
	isTruncated: boolean;
	redacted: string[];
	unavailable: string[];
}

let cache: Catalog = { credentials: [], groups: {}, projectGroups: [] };
const active = new Map<string, number>();

function showActive(ctx: ExtensionContext) {
	ctx.ui.setStatus("pi-credentials", active.size ? `🔑 ${[...active.keys()].join(", ")}` : undefined);
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
	} else if (parts.length === 1 && subcommand !== "list") {
		if (subcommand === "group") {
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
	if (selectedKind === "api-key") {
		const text = await ctx.ui.input("Allowed hosts", "api.example.com, *.example.org (empty means any host)");
		if (text === undefined) return undefined;
		hosts = text.split(",").map((host) => host.trim()).filter(Boolean);
	}
	return { kind: selectedKind, description: description.trim(), hosts };
}

async function runCommand(argumentText: string, ctx: ExtensionContext): Promise<string | undefined> {
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
			return [`${listing.name}: ${listing.description}`, `Kind: ${listing.kind}`, `Hosts: ${listing.hosts.join(", ") || "any"}`, `Apps: ${listing.apps.join(", ") || "any"}`, `Grants: ${listing.grants.join(", ") || "none"}`, listing.rotation ? `Rotate at: ${listing.rotation}` : ""].filter(Boolean).join("\n");
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
			const field = await ctx.ui.select(`Edit ${name}`, ["description", "kind", "hosts", "apps", "rotation link"]);
			if (!field) return undefined;
			const change: Record<string, unknown> = {};
			if (field === "kind") {
				const kind = await ctx.ui.select("Kind", kinds);
				if (!kind) return undefined;
				change.kind = kind;
			} else {
				const current = field === "hosts" ? listing.hosts.join(", ") : field === "apps" ? listing.apps.join(", ") : field === "description" ? listing.description : listing.rotation ?? "";
				const text = await ctx.ui.input(`New ${field} (now: ${current || "none"})`, field === "hosts" || field === "apps" ? "comma separated, empty means any" : "");
				if (text === undefined) return undefined;
				const list = text.split(",").map((item) => item.trim()).filter(Boolean);
				if (field === "hosts") change.hosts = list;
				else if (field === "apps") change.apps = list;
				else if (field === "description") change.description = text.trim();
				else change.rotation = text.trim();
			}
			await callHelper("edit", { name, ...change });
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
		default:
			throw new HelperError("unknown-subcommand", `Unknown subcommand ${subcommand}. Use ${Object.keys(subcommands).join(", ")}.`);
	}
}

async function offerGrant(name: string, ctx: ExtensionContext, signal?: AbortSignal): Promise<boolean> {
	if (!ctx.hasUI) return false;
	const catalog = await refresh(ctx.cwd);
	if (catalog.credentials.find((item) => item.name === name)?.kind !== "api-key") return false;
	const scopes = [...catalog.projectGroups, "global"];
	const choice = await ctx.ui.select(`An agent wants to use ${name}. Grant it?`, [...scopes.map((scope) => `Grant to ${scope}`), "Do not grant"], { signal });
	if (!choice || choice === "Do not grant") return false;
	await callHelper("grant", { name, scope: choice.slice("Grant to ".length) });
	await refresh(ctx.cwd);
	return true;
}

export default function piCredentials(pi: ExtensionAPI) {
	pi.on("session_start", async (_event, ctx) => {
		try { await refresh(ctx.cwd); }
		catch (error) { ctx.ui.notify(`pi-credentials: ${(error as Error).message}`, "warning"); }
	});

	pi.registerCommand("cred", {
		description: "Manage credentials that agents can use without seeing them",
		getArgumentCompletions: (argumentText) => completions(argumentText, cache),
		handler: async (argumentText, ctx) => {
			try {
				const message = await runCommand(argumentText, ctx);
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
		}, { additionalProperties: false }),
		async execute(_id, input, signal, _update, ctx) {
			const { name, ...request } = input;
			const send = () => callHelper<HTTPResponse>("request", { name, cwd: ctx.cwd, session: ctx.sessionManager.getSessionId(), request }, signal);
			active.set(name, (active.get(name) ?? 0) + 1);
			showActive(ctx);
			try {
				let response: HTTPResponse;
				try { response = await send(); }
				catch (error) {
					if (!(error instanceof HelperError) || error.code !== "not-granted" || !(await offerGrant(name, ctx, signal))) throw error;
					response = await send();
				}
				const notes = [response.isTruncated ? "Body truncated at 1 MB." : "", response.unavailable.length ? `Could not check output for: ${response.unavailable.join(", ")}.` : ""].filter(Boolean);
				const text = [`HTTP ${response.status}${response.contentType ? ` · ${response.contentType}` : ""}`, ...notes, "", response.body].join("\n");
				return { content: [{ type: "text", text }], details: { status: response.status, redacted: response.redacted } };
			} finally {
				const remaining = (active.get(name) ?? 1) - 1;
				if (remaining > 0) active.set(name, remaining);
				else active.delete(name);
				showActive(ctx);
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
			const value = await ctx.ui.input(`${input.reason} · value for ${input.name} (${input.kind})`, "Paste the secret, or press Escape to decline", { signal });
			if (!value) throw new Error("The user declined to enter the credential.");
			await callHelper("add", { name: input.name, value, kind: input.kind, description: input.description, hosts: input.hosts ?? [] });
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
