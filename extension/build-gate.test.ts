import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { BuildSpec } from "pi-compiled";
import { prepareHelper } from "./helper.ts";

function checkout(): BuildSpec {
	const root = mkdtempSync(join(tmpdir(), "pi-credentials-gate-"));
	writeFileSync(join(root, "source.txt"), "v1\n");
	writeFileSync(join(root, ".gitignore"), "bin/\n.swiftpm/\n");
	for (const args of [["init", "-q"], ["add", "."], ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init"]]) execFileSync("git", ["-C", root, ...args]);
	return { packageRoot: root, binary: "bin/helper", buildCommand: ["/bin/sh", "-c", "mkdir -p bin && touch bin/helper && chmod +x bin/helper"], inputs: ["source.txt"], overrideEnv: "PI_CREDENTIALS_GATE_TEST" };
}

function context(isApproved: boolean, isInteractive = true) {
	const asked: string[] = [];
	return { asked, ctx: { hasUI: isInteractive, ui: { confirm: async (title: string) => { asked.push(title); return isApproved; }, notify: () => undefined } } as never };
}

test("the helper is built and signed only after the user approves, and never without a prompt or from unchecked source", async () => {
	let build = checkout();
	const silent = context(true, false);
	await assert.rejects(prepareHelper(silent.ctx, build), { code: "helper-unavailable" });
	assert.equal(silent.asked.length, 0);

	writeFileSync(join(build.packageRoot, "source.txt"), "tampered\n");
	const tampered = context(true);
	await assert.rejects(prepareHelper(tampered.ctx, build), { code: "helper-build-refused" });
	assert.equal(tampered.asked.length, 0);

	build = checkout();
	mkdirSync(join(build.packageRoot, ".swiftpm"));
	const configured = context(true);
	await assert.rejects(prepareHelper(configured.ctx, build), (error: Error & { code: string }) => error.code === "helper-build-refused" && /\.swiftpm/.test(error.message));
	assert.equal(configured.asked.length, 0);
	rmSync(join(build.packageRoot, ".swiftpm"), { recursive: true });

	const declined = context(false);
	await assert.rejects(prepareHelper(declined.ctx, build), { code: "helper-unavailable" });
	assert.equal(declined.asked.length, 1);
	assert.equal(existsSync(join(build.packageRoot, "bin/helper")), false);

	const approved = context(true);
	await prepareHelper(approved.ctx, build);
	assert.equal(approved.asked.length, 1);
	assert.equal(existsSync(join(build.packageRoot, "bin/helper")), true);
	const again = context(true);
	await prepareHelper(again.ctx, build);
	assert.equal(again.asked.length, 0);
});

test("a helper override must be an absolute path to an executable, so a relative name is never run", async () => {
	const build = checkout();
	process.env.PI_CREDENTIALS_GATE_TEST = "helper";
	await assert.rejects(prepareHelper(context(true).ctx, build), { code: "build-failed" });
	process.env.PI_CREDENTIALS_GATE_TEST = "/usr/bin/true";
	await prepareHelper(context(true).ctx, build);
	delete process.env.PI_CREDENTIALS_GATE_TEST;
});
