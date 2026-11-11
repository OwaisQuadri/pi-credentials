import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

const directory = mkdtempSync(join(tmpdir(), "pi-root-session-"));
after(() => rmSync(directory, { recursive: true, force: true }));
const fixture = join(directory, "helper");
const protocol = join(directory, "protocol");
const submitted = join(directory, "submitted");
writeFileSync(fixture, `#!/usr/bin/env node
const fs = require("node:fs");
const { createInterface } = require("node:readline");
const protocol = fs.existsSync(${JSON.stringify(protocol)}) ? fs.readFileSync(${JSON.stringify(protocol)}, "utf8") : "1";
process.stdin.on("data", (chunk) => fs.appendFileSync(${JSON.stringify(submitted)}, chunk));
if (protocol === "legacy") {
  process.stdin.on("end", () => process.stdout.write(JSON.stringify({ error: { code: "unknown-command", message: "Unknown command" } })));
} else {
process.stdout.write(JSON.stringify(protocol === "error" ? { error: { code: "unknown-command", message: "Unsupported command" } } : { protocol: Number(protocol) }) + "\\n");
let count = 0;
createInterface({ input: process.stdin }).on("line", (line) => {
  const { command, input } = JSON.parse(line);
  if (input.operation === "exit") return process.exit(1);
  if (input.operation === "slow") return;
  if (input.operation === "invalid") return process.stdout.write("[]\\n");
  if (input.operation === "refuse") return process.stdout.write(JSON.stringify({ error: { code: "auth-denied", message: "Denied" } }) + "\\n");
  process.stdout.write(JSON.stringify({ command, input, count: ++count, pid: process.pid }) + "\\n");
});
}
`);
chmodSync(fixture, 0o700);
process.env.PI_CREDENTIALS_HELPER = fixture;
const { SudoSession } = await import("./sudo-session.ts");
delete process.env.PI_CREDENTIALS_HELPER;

type Reply = { command: string; input: { name: string }; count: number; pid: number };

test("unsupported helpers fail within a deadline before receiving a root command", { timeout: 10_000 }, async () => {
	const session = new SudoSession();
	try {
		for (const version of ["legacy", "0", "error"]) {
			writeFileSync(protocol, version);
			rmSync(submitted, { force: true });
			const code = version === "error" ? "unknown-command" : "helper-incompatible";
			await assert.rejects(session.call("ssh-sudo", { name: "one" }), { code });
			if (version === "error") await assert.rejects(session.call("sudo", { name: "two" }), { code });
			assert.equal(existsSync(submitted) ? readFileSync(submitted, "utf8") : "", "");
		}
		rmSync(protocol);
		const fresh = await session.call<Reply>("sudo", { name: "one" });
		assert.equal(fresh.count, 1);
	} finally { rmSync(protocol, { force: true }); session.close(); }
});

test("cancellation during helper startup submits no root command and clears the helper", async () => {
	const session = new SudoSession();
	const controller = new AbortController();
	try {
		writeFileSync(protocol, "legacy");
		rmSync(submitted, { force: true });
		const pending = assert.rejects(session.call("sudo", { name: "one" }, controller.signal), { code: "aborted" });
		await new Promise((resolve) => setImmediate(resolve));
		controller.abort();
		await pending;
		assert.equal(existsSync(submitted) ? readFileSync(submitted, "utf8") : "", "");
		rmSync(protocol);
		const fresh = await session.call<Reply>("sudo", { name: "one" });
		assert.equal(fresh.count, 1);
	} finally { rmSync(protocol, { force: true }); session.close(); }
});

test("root calls share one helper, serialize concurrent requests and do not retry refusals", async () => {
	const session = new SudoSession();
	try {
		const [first, second] = await Promise.all([
			session.call<Reply>("sudo", { name: "one" }),
			session.call<Reply>("ssh-sudo", { name: "two" }),
		]);
		assert.equal(first.count, 1);
		assert.equal(second.count, 2);
		assert.equal(first.pid, second.pid);
		assert.equal(first.input.name, "one");
		assert.equal(second.input.name, "two");
		assert.equal(second.command, "ssh-sudo");
		await assert.rejects(session.call("sudo", { operation: "refuse" }), { code: "auth-denied" });
		const third = await session.call<Reply>("sudo", { name: "three" });
		assert.equal(third.count, 3);
		assert.equal(third.pid, first.pid);
	} finally { session.close(); }
});

test("a new session uses a new helper and a closed session cannot start another", async () => {
	const first = new SudoSession();
	const second = new SudoSession();
	try {
		const old = await first.call<Reply>("sudo", { name: "one" });
		first.close();
		first.close();
		await assert.rejects(first.call("sudo", {}), { code: "aborted" });
		const fresh = await second.call<Reply>("sudo", { name: "one" });
		assert.notEqual(old.pid, fresh.pid);
		assert.equal(fresh.count, 1);
	} finally { first.close(); second.close(); }
});

test("cancellation clears the helper, including queued requests, without retrying the command", async () => {
	const session = new SudoSession();
	const controller = new AbortController();
	try {
		const old = await session.call<Reply>("sudo", { name: "one" });
		const pending = session.call("ssh-sudo", { operation: "slow" }, controller.signal);
		const rejected = assert.rejects(pending, { code: "aborted" });
		const queued = assert.rejects(session.call("sudo", {}, controller.signal), { code: "aborted" });
		await new Promise((resolve) => setImmediate(resolve));
		controller.abort();
		await Promise.all([rejected, queued]);
		const fresh = await session.call<Reply>("sudo", { name: "one" });
		assert.notEqual(old.pid, fresh.pid);
		assert.equal(fresh.count, 1);
		await assert.rejects(session.call("sudo", {}, controller.signal), { code: "aborted" });
	} finally { session.close(); }
});

test("cancelling only a queued request clears approval and does not replay active work", async () => {
	const session = new SudoSession();
	const active = new AbortController();
	const queued = new AbortController();
	const cleanup = setTimeout(() => session.close(), 5_000);
	try {
		const old = await session.call<Reply>("sudo", { name: "one" });
		const running = assert.rejects(session.call("ssh-sudo", { operation: "slow" }, active.signal), { code: "aborted" });
		const waiting = assert.rejects(session.call("sudo", {}, queued.signal), { code: "aborted" });
		await new Promise((resolve) => setImmediate(resolve));
		queued.abort();
		await Promise.all([running, waiting]);
		assert.equal(active.signal.aborted, false);
		const fresh = await session.call<Reply>("sudo", { name: "one" });
		assert.notEqual(old.pid, fresh.pid);
		assert.equal(fresh.count, 1);
	} finally { clearTimeout(cleanup); session.close(); }
});

test("an already cancelled request clears earlier approval before the next call", async () => {
	const session = new SudoSession();
	const controller = new AbortController();
	try {
		const old = await session.call<Reply>("sudo", { name: "one" });
		controller.abort();
		await assert.rejects(session.call("sudo", {}, controller.signal), { code: "aborted" });
		const fresh = await session.call<Reply>("sudo", { name: "one" });
		assert.notEqual(old.pid, fresh.pid);
		assert.equal(fresh.count, 1);
	} finally { session.close(); }
});

test("helper exit and malformed output lose approval and never replay the failed request", async () => {
	const session = new SudoSession();
	try {
		for (const [operation, code] of [["exit", "helper-unavailable"], ["invalid", "helper-output"]]) {
			const old = await session.call<Reply>("sudo", { name: "one" });
			await assert.rejects(session.call("ssh-sudo", { operation }), { code });
			const fresh = await session.call<Reply>("sudo", { name: "one" });
			assert.notEqual(old.pid, fresh.pid);
			assert.equal(fresh.count, 1);
		}
	} finally { session.close(); }
});
