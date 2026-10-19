import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, test } from "node:test";

const directory = mkdtempSync(join(tmpdir(), "pi-credentials-test-"));
after(() => rmSync(directory, { recursive: true, force: true }));
const fake = join(directory, "helper");
writeFileSync(fake, `#!/bin/sh
input=$(cat)
case "$1" in
  list) echo '{"credentials":[{"name":"key","description":"","kind":"api-key","hosts":[],"apps":[],"grants":[],"isGranted":false}],"groups":{},"projectGroups":[]}' ;;
  redact)
    [ -e "${directory}/broken" ] && exit 1
    printf '%s' "$input" | /usr/bin/python3 -c 'import json,sys; t=json.load(sys.stdin)["text"]; r=t.replace("SECRET","[cred:key]"); print(json.dumps({"text":r,"redacted":["key"] if r!=t else [],"unavailable":[]}))' ;;
esac
`);
chmodSync(fake, 0o755);
process.env.PI_CREDENTIALS_HELPER = fake;

type Handler = (event: unknown, ctx: unknown) => Promise<any>;
const handlers: Record<string, Handler> = {};
const { default: extension } = await import("./index.ts");
extension({
	on: (name: string, handler: Handler) => { handlers[name] = handler; },
	registerCommand: () => undefined,
	registerTool: () => undefined,
} as never);

test("credential variables leave the Pi process and protected files stay unread", async () => {
	process.env.LEAKED_KEY = "xxSECRETxx";
	process.env.HARMLESS_SETTING = "plain-value";
	const notes: string[] = [];
	await handlers.session_start({}, { cwd: directory, ui: { notify: (text: string) => notes.push(text) } });
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
});
