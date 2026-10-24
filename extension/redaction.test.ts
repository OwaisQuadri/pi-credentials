import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, test } from "node:test";
import { credentialRedactionDiscoveryEvent, type CredentialRedactionServiceV1 } from "./redaction-service.ts";

const directory = mkdtempSync(join(tmpdir(), "pi-credentials-test-"));
after(() => rmSync(directory, { recursive: true, force: true }));
const fake = join(directory, "helper");
writeFileSync(fake, `#!/bin/sh
input=$(cat)
case "$1" in
  sudo|ssh-sudo)
    printf '%s\\n' "$1" >> "${directory}/sudo-calls"
    printf '%s' "$input" > "${directory}/sudo.json"
    if [ -e "${directory}/sudo-response" ]; then cat "${directory}/sudo-response"; else echo '{"status":0,"stdout":"fixture","stderr":"","isTruncated":false,"isTimedOut":false}'; fi ;;
  add)
    printf '%s' "$input" > "${directory}/add.json"
    echo '{"added":true}' ;;
  request)
    printf '%s' "$input" > "${directory}/request.json"
    printf '%s' "$input" | /usr/bin/python3 -c 'import json,sys; r=json.load(sys.stdin)["request"]; p=r.get("outputFile"); print(json.dumps({"error":{"code":"output-file-refused","message":"Existing paths are refused."}} if p=="existing" else {"status":200,"body":"NEVER_RETURN","isTruncated":False,"redacted":[],"unavailable":[]} if p=="legacy" else {"status":200,"contentType":"application/octet-stream","outputFile":p,"byteCount":1000001,"body":"NEVER_RETURN","isTruncated":False,"redacted":[],"unavailable":[]} if p else {"status":200,"body":"text response","isTruncated":False,"redacted":[],"unavailable":[]}))' ;;
  list)
    if [ -f "${directory}/catalog.json" ]; then cat "${directory}/catalog.json";
    else echo '{"credentials":[{"name":"key","description":"","kind":"api-key","hosts":[],"apps":[],"grants":[],"isGranted":false}],"groups":{},"projectGroups":[],"projects":{},"projectIDs":[]}'; fi ;;
  project-create|project-rename|project-membership)
    printf '%s' "$input" > "${directory}/$1.json"
    if [ -f "${directory}/denied" ]; then echo '{"error":{"code":"auth-denied","message":"Owner approval denied."}}'; exit 1; fi
    if [ "$1" = project-rename ]; then
      printf '%s' "$input" | /usr/bin/python3 -c 'import json,sys; i=json.load(sys.stdin); p="${directory}/catalog.json"; c=json.load(open(p)); c["projects"][i["project"]]["name"]=i["name"]; json.dump(c,open(p,"w"))'
    fi
    echo '{"project":"11111111-1111-4111-8111-111111111111"}' ;;
  grant|revoke)
    printf '%s' "$input" > "${directory}/$1.json"
    echo '{"changed":true}' ;;
  env)
    printf '%s' "$input" > "${directory}/env.json"
    echo '{"error":{"code":"not-granted","message":"The helper refused access."}}' ;;
  redact)
    [ -e "${directory}/broken" ] && exit 1
    if [ -e "${directory}/redaction-response" ]; then cat "${directory}/redaction-response"; exit 0; fi
    printf '%s' "$input" | /usr/bin/python3 -c 'import json,os,sys; t=json.load(sys.stdin)["text"]; r=t.replace("SECRET","[cred:key]"); print(json.dumps({"text":r,"redacted":["key"] if r!=t else [],"unavailable":["key"] if os.path.exists("${directory}/locked") else []}))' ;;
esac
`);
chmodSync(fake, 0o755);
const originalEnvironment = process.env;
process.env = { HOME: directory, TMPDIR: directory, PATH: "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin", PI_CREDENTIALS_HELPER: fake };
after(() => { process.env = originalEnvironment; });

type Handler = (event: unknown, ctx: unknown) => Promise<any>;
const handlers: Record<string, Handler> = {};
const events: Record<string, (payload: unknown) => void> = {};
const tools: Record<string, { execute: (...args: any[]) => Promise<any> }> = {};
const commands: Record<string, {
	handler: (text: string, ctx: any) => Promise<void>;
	getArgumentCompletions: (text: string) => { value: string; label: string; description?: string }[] | null;
}> = {};
const { default: extension } = await import("./index.ts");
extension({
	on: (name: string, handler: Handler) => {
		const previous = handlers[name];
		handlers[name] = previous ? async (event, ctx) => (await previous(event, ctx)) ?? handler(event, ctx) : handler;
	},
	registerCommand: (name: string, command: typeof commands[string]) => { commands[name] = command; },
	events: { on: (channel: string, handler: (payload: unknown) => void) => { events[channel] = handler; return () => { delete events[channel]; }; }, emit: () => undefined },
	registerEntryRenderer: () => undefined,
	appendEntry: () => undefined,
	registerTool: (tool: { name: string; execute: (...args: any[]) => Promise<any> }) => { tools[tool.name] = tool; },
} as never);

test("piCredentials session_shutdown revokes redaction discovery and restart requires successful startup", async () => {
	const ctx = { cwd: directory, hasUI: false, sessionManager: { getSessionDir: () => undefined }, ui: { notify: () => undefined } };
	const request = { version: 1 as const, requestID: "runtime-fixture", pieces: ["clean"] };
	const check = (service: CredentialRedactionServiceV1, pieces = request.pieces) => service.redact({ ...request, pieces }, { signal: new AbortController().signal });
	const discover = () => {
		const services: CredentialRedactionServiceV1[] = [];
		events[credentialRedactionDiscoveryEvent]?.({ version: 1, signal: new AbortController().signal, provide: (service: CredentialRedactionServiceV1) => services.push(service) });
		assert.equal(services.length, 1);
		return services[0];
	};
	const initial = discover();
	assert.deepEqual(await check(initial), { status: "blocked", requestID: request.requestID, code: "not-ready" });
	await handlers.session_start({}, ctx);
	assert.equal((await check(initial)).status, "checked");
	assert.deepEqual(await check(initial, []), { status: "checked", requestID: request.requestID, policy: "pi-credentials/redact-v1", pieces: [] });
	writeFileSync(join(directory, "locked"), "");
	assert.deepEqual(await check(initial), { status: "blocked", requestID: request.requestID, code: "unavailable" });
	assert.deepEqual(await check(initial, []), { status: "blocked", requestID: request.requestID, code: "unavailable" });
	rmSync(join(directory, "locked"));
	for (const output of [{ text: "unexpected", redacted: [], unavailable: [] }, { text: "\uD800", redacted: [], unavailable: [] }, { text: "clean", redacted: [], unavailable: "invalid" }]) {
		writeFileSync(join(directory, "redaction-response"), JSON.stringify(output));
		assert.deepEqual(await check(initial), { status: "blocked", requestID: request.requestID, code: "failed" });
		assert.deepEqual(await check(initial, []), { status: "blocked", requestID: request.requestID, code: "failed" });
	}
	rmSync(join(directory, "redaction-response"));
	await handlers.session_shutdown({}, ctx);
	assert.equal(events[credentialRedactionDiscoveryEvent], undefined);
	assert.deepEqual(await check(initial), { status: "blocked", requestID: request.requestID, code: "not-ready" });
	writeFileSync(join(directory, "broken"), "");
	await handlers.session_start({}, ctx);
	const restarted = discover();
	assert.notEqual(restarted, initial);
	assert.deepEqual(await check(restarted), { status: "blocked", requestID: request.requestID, code: "not-ready" });
	rmSync(join(directory, "broken"));
	await handlers.session_start({}, ctx);
	assert.equal((await check(restarted)).status, "checked");
	assert.deepEqual(await check(initial), { status: "blocked", requestID: request.requestID, code: "not-ready" });
	await handlers.session_shutdown({}, ctx);
});

test("credential variables leave the Pi process and protected files stay unread", async () => {
	process.env.LEAKED_KEY = "xxSECRETxx";
	process.env.HARMLESS_SETTING = "plain-value";
	const notes: string[] = [];
	await handlers.session_start({}, { cwd: directory, hasUI: true, ui: { notify: () => undefined, setWidget: (_key: string, lines?: string[]) => { if (lines) notes.push(...lines); } } });
	assert.equal(process.env.LEAKED_KEY, undefined);
	assert.equal(process.env.HARMLESS_SETTING, "plain-value");
	assert.match(notes.join("\n"), /LEAKED_KEY/);

	process.env.PI_CODING_AGENT_DIR = join(directory, "agent");
	const ctx = { cwd: directory };
	for (const path of [".env", "app/.env.local", "@.env", ".env/", "./x/../.env", ".ENV", `file://${directory}/%2Eenv`, join(directory, "agent//auth.json"), `${directory}/agent/./mcp-auth.json`]) {
		assert.equal((await handlers.tool_call({ toolName: "read", input: { path } }, ctx))?.block, true, path);
	}
	const tree = join(directory, "tree");
	for (const [file, text] of [["backend/.env", "A=1"], [".env.development", "B=2"], ["src/a.ts", "x"], ["README.md", "x"], [".env.example", "C="]]) {
		mkdirSync(dirname(join(tree, file)), { recursive: true });
		writeFileSync(join(tree, file), text);
	}
	mkdirSync(join(directory, "agent"), { recursive: true });
	writeFileSync(join(directory, "agent", "auth.json"), "{}");
	const treeCtx = { cwd: tree };
	const grep = (input: { path?: string; glob?: string }, context = treeCtx) => handlers.tool_call({ toolName: "grep", input: { pattern: ".", ...input } }, context);
	assert.equal((await grep({ path: ".env.development" }))?.block, true);
	for (const glob of ["**/.env*", "*", ".e*", "**", "{a,.env}", "!*.ts", "**/backend/.env", ".env.dev*", "*.development", "\\.env", "[].]env"]) {
		assert.equal((await grep({ glob }))?.block, true, glob);
	}
	assert.equal((await grep({}))?.block, true);
	const config = join(directory, "rgconfig");
	writeFileSync(config, "--color=always\n--path-separator=\\\n");
	process.env.RIPGREP_CONFIG_PATH = config;
	assert.equal((await grep({}))?.block, true);
	assert.equal(await grep({ path: "src" }), undefined);
	delete process.env.RIPGREP_CONFIG_PATH;
	for (const glob of ["*.ts", "*.md", ".env.example"]) assert.equal(await grep({ glob }), undefined, glob);
	assert.equal(await grep({ path: "src" }), undefined);
	mkdirSync(join(tree, " spaced"));
	writeFileSync(join(tree, " spaced", ".env"), "D=4");
	assert.equal((await grep({ path: " spaced" }))?.block, true);
	assert.match((await grep({ path: "missing" }))?.reason ?? "", /could not list this path/);
	for (const input of [{ path: join(directory, "agent"), glob: "*.json" }, { path: join(directory, "agent") }, { path: `@${join(directory, "agent")}`, glob: "auth.json" }, { path: directory }]) {
		assert.equal((await grep(input))?.block, true, JSON.stringify(input));
	}
	for (const path of [".env.example", "auth.json", "src/env.ts"]) {
		assert.equal(await handlers.tool_call({ toolName: "read", input: { path } }, ctx), undefined, path);
	}
	delete process.env.PI_CODING_AGENT_DIR;
});

test("project commands refresh names and forward membership and grants to the helper", async () => {
	const id = "11111111-1111-4111-8111-111111111111";
	const scope = `project:${id}`;
	const repository = "/fixture/repository with spaces/.git";
	const fixture = {
		credentials: [{ name: "key", description: "Fixture key", kind: "api-key", hosts: [], apps: [], grants: [scope], isGranted: true }],
		groups: { work: ["example.test/org/*"] }, projectGroups: [],
		projects: { [id]: { name: "Example project", repositories: [repository] } }, projectIDs: [id], repository,
	};
	writeFileSync(join(directory, "catalog.json"), JSON.stringify(fixture));
	const notes: string[] = [];
	const ctx = { cwd: directory, sessionManager: { getSessionId: () => "fixture" }, ui: { notify: (text: string) => notes.push(text) } };
	const run = (text: string) => commands.project.handler(text, ctx);
	try {
		await run("");
		assert.match(notes.pop() ?? "", /Example project/);
		assert.deepEqual(commands.project.getArgumentCompletions("")?.map((item) => item.label), ["create", "list", "rename", "inspect", "membership"]);
		assert.deepEqual(commands.project.getArgumentCompletions("membership ")?.map((item) => item.label), ["add", "remove"]);
		for (const prefix of ["rename ", "inspect ", "membership add ", "membership remove "]) {
			assert.deepEqual(commands.project.getArgumentCompletions(prefix), [{ value: `${prefix}${id} `, label: id, description: "Example project" }]);
		}
		assert.equal(commands.project.getArgumentCompletions(`membership remove ${id} /fixture/repository with `)?.[0].value, `membership remove ${id} ${repository} `);
		await run("create New  readable name");
		assert.deepEqual(JSON.parse(readFileSync(join(directory, "project-create.json"), "utf8")), { name: "New  readable name" });
		await run(`rename ${id} Renamed project`);
		assert.deepEqual(JSON.parse(readFileSync(join(directory, "project-rename.json"), "utf8")), { project: id, name: "Renamed project" });
		assert.equal(commands.project.getArgumentCompletions("inspect ")?.[0].description, "Renamed project");
		await run(`inspect ${id}`);
		assert.match(notes.pop() ?? "", /Renamed project.*\nRepositories: .*\nCredential grants: key/);
		await run(`membership add ${id} /fixture/repository  with spaces`);
		assert.deepEqual(JSON.parse(readFileSync(join(directory, "project-membership.json"), "utf8")), { project: id, operation: "add", cwd: directory, path: "/fixture/repository  with spaces" });
		await run(`membership remove ${id}`);
		assert.deepEqual(JSON.parse(readFileSync(join(directory, "project-membership.json"), "utf8")), { project: id, operation: "remove", cwd: directory });
		assert.match(commands.cred.getArgumentCompletions("grant key project:")?.[0].description ?? "", /Renamed project/);
		assert.equal(commands.cred.getArgumentCompletions("revoke key ")?.[0].label, scope);
		for (const command of ["grant", "revoke"]) {
			await commands.cred.handler(`${command} key ${scope}`, ctx);
			assert.deepEqual(JSON.parse(readFileSync(join(directory, `${command}.json`), "utf8")), { name: "key", scope });
		}
		writeFileSync(join(directory, "denied"), "");
		await run(`membership add ${id}`);
		assert.equal(notes.pop(), "Owner approval denied.");
		await assert.rejects(tools.cred_env.execute("fixture", {}, undefined, undefined, ctx), /helper refused access/);
		assert.deepEqual(JSON.parse(readFileSync(join(directory, "env.json"), "utf8")), { cwd: directory, session: "fixture" });
	} finally {
		rmSync(join(directory, "catalog.json"));
		rmSync(join(directory, "denied"), { force: true });
	}
});

test("cred_request forwards outputFile and returns only file metadata", async () => {
	const ctx = { cwd: directory, sessionManager: { getSessionId: () => "fixture-session" }, ui: { setStatus: () => undefined } };
	const input = { name: "key", method: "POST", url: "https://api.example.test/media", body: "fixture", outputFile: "media.bin" };
	const result = await tools.cred_request.execute("fixture", input, undefined, undefined, ctx);
	const forwarded = JSON.parse(readFileSync(join(directory, "request.json"), "utf8"));
	assert.deepEqual(forwarded, { cwd: directory, session: "fixture-session", name: "key", request: { method: input.method, url: input.url, body: input.body, outputFile: input.outputFile } });
	assert.deepEqual(result.details, { status: 200, contentType: "application/octet-stream", outputFile: "media.bin", byteCount: 1000001, redacted: [] });
	assert.match(result.content[0].text, /Saved 1000001 bytes to media.bin/);
	assert.doesNotMatch(JSON.stringify(result), /NEVER_RETURN/);
	await assert.rejects(tools.cred_request.execute("fixture", { ...input, outputFile: "existing" }, undefined, undefined, ctx), /Existing paths are refused/);
	await assert.rejects(tools.cred_request.execute("fixture", { ...input, outputFile: "legacy" }, undefined, undefined, ctx), /helper did not confirm a saved file/);
	const text = await tools.cred_request.execute("fixture", { name: "key", method: "GET", url: input.url }, undefined, undefined, ctx);
	assert.match(text.content[0].text, /text response/);
	assert.deepEqual(text.details, { status: 200, redacted: [] });
});

test("tool output never reaches the model with a registered key in it", async () => {
	const result = await handlers.tool_result({
		content: [{ type: "text", text: "a SECRET b" }, { type: "image", data: "x", mimeType: "image/png" }, { type: "text", text: "bin\u0000ary" }],
		structuredContent: { token: "SECRET" },
		details: { output: "SECRET" },
	}, {});
	assert.deepEqual(result.content.map((part: any) => part.text), ["a [cred:key] b", undefined, "bin\u0000ary"]);
	assert.deepEqual(result.details, { output: "[cred:key]" });
	assert.deepEqual(result.structuredContent, { token: "[cred:key]" });
	assert.equal(await handlers.tool_result({ content: [{ type: "text", text: "clean" }] }, {}), undefined);

	const circular: Record<string, unknown> = { token: "SECRET" };
	circular.self = circular;
	const unserializable = await handlers.tool_result({ content: [{ type: "text", text: "a SECRET b" }], details: circular }, {});
	assert.equal(unserializable.isError, true);
	assert.deepEqual(unserializable.details, {});

	writeFileSync(join(directory, "broken"), "");
	const withheld = await handlers.tool_result({ content: [{ type: "text", text: "a SECRET b" }], structuredContent: { token: "SECRET" }, details: { output: "SECRET" } }, {});
	assert.equal(withheld.isError, true);
	assert.deepEqual(withheld.details, {});

	assert.doesNotMatch(JSON.stringify(withheld), /SECRET/);
	rmSync(join(directory, "broken"));
});

test("messages and tool call arguments never reach the model with a registered key in them", async () => {
	const notes: string[] = [];
	const ctx = { cwd: directory, ui: { notify: (text: string) => notes.push(text) } };
	assert.deepEqual(await handlers.input({ text: "use SECRET now" }, ctx), { action: "transform", text: "use [cred:key] now", images: undefined });
	assert.deepEqual(await handlers.input({ text: "clean" }, ctx), { action: "continue" });
	const call = { toolName: "bash", input: { command: "echo SECRET" } };
	assert.equal(await handlers.tool_call(call, ctx), undefined);
	assert.deepEqual(call.input, { command: "echo [cred:key]" });
	const keyed = { toolName: "bash", input: { SECRET: 1 } };
	await handlers.tool_call(keyed, ctx);
	assert.deepEqual(keyed.input, { "[cred:key]": 1 });

	writeFileSync(join(directory, "locked"), "");
	assert.deepEqual(await handlers.input({ text: "clean" }, ctx), { action: "handled" });
	assert.match(notes.at(-1) ?? "", /could not read key/);
	const widgets: Array<[string, string[] | undefined]> = [];
	const ui = { cwd: directory, hasUI: true, ui: { notify: () => undefined, setWidget: (key: string, lines?: string[]) => { widgets.push([key, lines]); } } };
	assert.deepEqual(await handlers.input({ text: "clean" }, ui), { action: "handled" });
	assert.deepEqual(widgets.slice(0, 2), [["pi-credentials-build", undefined], ["pi-credentials-notice", undefined]]);
	assert.equal(widgets[2][0], "pi-credentials-notice");
	assert.match(widgets[2][1]?.[0] ?? "", /could not read key/);
	assert.equal((await handlers.tool_call({ toolName: "bash", input: { command: "ls" } }, ctx))?.block, true);
	assert.equal((await handlers.tool_result({ content: [{ type: "text", text: "clean" }] }, ctx)).isError, true);
	rmSync(join(directory, "locked"));

	writeFileSync(join(directory, "broken"), "");
	assert.deepEqual(await handlers.input({ text: "use SECRET now" }, ctx), { action: "handled" });
	assert.equal((await handlers.tool_call({ toolName: "bash", input: { command: "echo SECRET" } }, ctx))?.block, true);
	rmSync(join(directory, "broken"));
});

test("remote sudo never falls back locally and preserves admission refusals", async () => {
	const ctx = { cwd: directory, hasUI: true, sessionManager: { getSessionId: () => "fixture-session" }, ui: { setStatus: () => undefined, select: async () => { throw new Error("must not offer grant"); } } };
	const input = { name: "password", command: ["/usr/bin/id"] };
	const response = join(directory, "sudo-response");
	const calls = () => readFileSync(join(directory, "sudo-calls"), "utf8").trim().split("\n");
	const execute = (request: object, signal?: AbortSignal, context = ctx) => tools.cred_sudo.execute("fixture", request, signal, undefined, context);
	await assert.rejects(execute(input, undefined, { ...ctx, hasUI: false }), /No user is present/);
	const local = await execute(input);
	assert.equal(local.isError, false);
	assert.equal(local.content[0].text, "Exit status 0\nstdout:\nfixture");
	assert.deepEqual(JSON.parse(readFileSync(join(directory, "sudo.json"), "utf8")), { cwd: directory, session: "fixture-session", name: "password", arguments: input.command });
	await execute({ ...input, sshTarget: "fixture-alias" });
	assert.deepEqual(JSON.parse(readFileSync(join(directory, "sudo.json"), "utf8")), { cwd: directory, session: "fixture-session", name: "password", arguments: input.command, sshTarget: "fixture-alias" });
	for (const [code, message] of [["invalid-arguments", "empty target refused"], ["wrong-kind", "wrong kind"], ["auth-denied", "approval denied"], ["unknown-command", "unknown operation"]]) {
		writeFileSync(response, JSON.stringify({ error: { code, message } }));
		await assert.rejects(execute({ ...input, sshTarget: "" }), code === "unknown-command" ? /Rebuild.*helper/ : new RegExp(message));
	}
	assert.deepEqual(calls(), ["sudo", "ssh-sudo", "ssh-sudo", "ssh-sudo", "ssh-sudo", "ssh-sudo"]);
	rmSync(response);
});

test("remote interruption and malformed responses never claim stopped or trigger retries", async () => {
	const statuses: unknown[] = [];
	const ctx = { cwd: directory, hasUI: true, sessionManager: { getSessionId: () => "fixture-session" }, ui: { setStatus: (...args: unknown[]) => statuses.push(args[1]) } };
	const input = { name: "password", command: ["/usr/bin/id"], sshTarget: "fixture-alias" };
	const valid = { status: 0, stdout: "", stderr: "", isTruncated: false, isTimedOut: false };
	const response = join(directory, "sudo-response");
	const calls = () => readFileSync(join(directory, "sudo-calls"), "utf8").trim().split("\n").length;
	for (const value of [{ ...valid, isTimedOut: true }, { ...valid, status: -1 }, { ...valid, status: 255 }, { ...valid, status: 1.5 }, { ...valid, isTimedOut: "false" }, {}, null, [], "invalid shape", { error: true }, { error: { code: "wrong-kind", message: 3 } },
		...["ssh-sudo-interrupted", "cancelled", "aborted", "timeout", "helper-output", "helper-unavailable"].map((code) => ({ error: { code, message: "fixture" } }))]) {
		writeFileSync(response, JSON.stringify(value));
		const before = calls();
		const result = await tools.cred_sudo.execute("fixture", input, undefined, undefined, ctx);
		assert.equal(result.isError, true);
		assert.match(result.content[0].text, /Remote completion was not confirmed.*may still be running/);
		assert.doesNotMatch(result.content[0].text, /stopped|successful/i);
		assert.equal(calls(), before + 1);
		assert.equal(statuses.at(-1), undefined);
	}
	for (const text of ["invalid JSON", ""]) {
		writeFileSync(response, text);
		const result = await tools.cred_sudo.execute("fixture", input, undefined, undefined, ctx);
		assert.equal(result.isError, true);
		assert.match(result.content[0].text, /Remote completion was not confirmed/);
	}
	const aborted = new AbortController();
	aborted.abort();
	const result = await tools.cred_sudo.execute("fixture", input, aborted.signal, undefined, ctx);
	assert.equal(result.isError, true);
	assert.match(result.content[0].text, /Remote completion was not confirmed/);
	writeFileSync(response, JSON.stringify(valid));
	const late = new AbortController();
	const lateCtx = { ...ctx, ui: { setStatus: (_key: string, value: string | undefined) => { if (value === undefined) late.abort(); } } };
	const lateResult = await tools.cred_sudo.execute("fixture", input, late.signal, undefined, lateCtx);
	assert.equal(late.signal.aborted, true);
	assert.equal(lateResult.isError, true);
	assert.match(lateResult.content[0].text, /Remote completion was not confirmed/);
	rmSync(response);
});

test("cred_ask saves a secret handle once and refuses unknown handles", async () => {
	const ctx = { cwd: directory, hasUI: true, ui: { input: async () => { throw new Error("must not prompt"); } } };
	events["ask-user-question:secret"]({ handle: "{{secret:0011aabb}}", value: "handle-value-123" });
	const input = { name: "saved", reason: "test", kind: "api-key", description: "fixture", secret: "{{secret:0011aabb}}" };
	const result = await tools.cred_ask.execute("fixture", input, undefined, undefined, ctx);
	assert.equal(JSON.parse(readFileSync(join(directory, "add.json"), "utf8")).value, "handle-value-123");
	assert.doesNotMatch(JSON.stringify(result), /handle-value-123/);
	await assert.rejects(tools.cred_ask.execute("fixture", input, undefined, undefined, ctx), /already used secret handle/);
});
