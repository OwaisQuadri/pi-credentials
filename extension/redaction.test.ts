import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, test } from "node:test";

const directory = mkdtempSync(join(tmpdir(), "pi-credentials-test-"));
after(() => rmSync(directory, { recursive: true, force: true }));
const fake = join(directory, "helper");
writeFileSync(fake, `#!/bin/sh
input=$(cat)
case "$1" in
  add)
    printf '%s' "$input" > "${directory}/add.json"
    echo '{"added":true}' ;;
  request)
    printf '%s' "$input" > "${directory}/request.json"
    printf '%s' "$input" | /usr/bin/python3 -c 'import json,sys; r=json.load(sys.stdin)["request"]; p=r.get("outputFile"); print(json.dumps({"error":{"code":"output-file-refused","message":"Existing paths are refused."}} if p=="existing" else {"status":200,"body":"NEVER_RETURN","isTruncated":False,"redacted":[],"unavailable":[]} if p=="legacy" else {"status":200,"contentType":"application/octet-stream","outputFile":p,"byteCount":1000001,"body":"NEVER_RETURN","isTruncated":False,"redacted":[],"unavailable":[]} if p else {"status":200,"body":"text response","isTruncated":False,"redacted":[],"unavailable":[]}))' ;;
  list) echo '{"credentials":[{"name":"key","description":"","kind":"api-key","hosts":[],"apps":[],"grants":[],"isGranted":false}],"groups":{},"projectGroups":[]}' ;;
  redact)
    [ -e "${directory}/broken" ] && exit 1
    printf '%s' "$input" | /usr/bin/python3 -c 'import json,os,sys; t=json.load(sys.stdin)["text"]; r=t.replace("SECRET","[cred:key]"); print(json.dumps({"text":r,"redacted":["key"] if r!=t else [],"unavailable":["key"] if os.path.exists("${directory}/locked") else []}))' ;;
esac
`);
chmodSync(fake, 0o755);
process.env.PI_CREDENTIALS_HELPER = fake;

type Handler = (event: unknown, ctx: unknown) => Promise<any>;
const handlers: Record<string, Handler> = {};
const events: Record<string, (payload: unknown) => void> = {};
const tools: Record<string, { execute: (...args: any[]) => Promise<any> }> = {};
const { default: extension } = await import("./index.ts");
extension({
	on: (name: string, handler: Handler) => {
		const previous = handlers[name];
		handlers[name] = previous ? async (event, ctx) => (await previous(event, ctx)) ?? handler(event, ctx) : handler;
	},
	registerCommand: () => undefined,
	events: { on: (channel: string, handler: (payload: unknown) => void) => { events[channel] = handler; }, emit: () => undefined },
	registerEntryRenderer: () => undefined,
	appendEntry: () => undefined,
	registerTool: (tool: { name: string; execute: (...args: any[]) => Promise<any> }) => { tools[tool.name] = tool; },
} as never);

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

test("cred_ask saves a secret handle once and refuses unknown handles", async () => {
	const ctx = { cwd: directory, hasUI: true, ui: { input: async () => { throw new Error("must not prompt"); } } };
	events["ask-user-question:secret"]({ handle: "{{secret:0011aabb}}", value: "handle-value-123" });
	const input = { name: "saved", reason: "test", kind: "api-key", description: "fixture", secret: "{{secret:0011aabb}}" };
	const result = await tools.cred_ask.execute("fixture", input, undefined, undefined, ctx);
	assert.equal(JSON.parse(readFileSync(join(directory, "add.json"), "utf8")).value, "handle-value-123");
	assert.doesNotMatch(JSON.stringify(result), /handle-value-123/);
	await assert.rejects(tools.cred_ask.execute("fixture", input, undefined, undefined, ctx), /already used secret handle/);
});
