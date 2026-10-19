import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
await handlers.session_start({}, { cwd: directory, ui: { notify: () => undefined } });

test("tool output never reaches the model with a registered key in it", async () => {
	const result = await handlers.tool_result({
		content: [{ type: "text", text: "a SECRET b" }, { type: "image", data: "x", mimeType: "image/png" }, { type: "text", text: "clean" }],
		structuredContent: { token: "SECRET" },
	}, {});
	assert.deepEqual(result.content.map((part: any) => part.text), ["a [cred:key] b", undefined, "clean"]);
	assert.deepEqual(result.structuredContent, { token: "[cred:key]" });
	assert.equal(await handlers.tool_result({ content: [{ type: "text", text: "clean" }] }, {}), undefined);

	writeFileSync(join(directory, "broken"), "");
	const withheld = await handlers.tool_result({ content: [{ type: "text", text: "a SECRET b" }], structuredContent: { token: "SECRET" } }, {});
	assert.equal(withheld.isError, true);
	assert.doesNotMatch(JSON.stringify(withheld), /SECRET/);
});
