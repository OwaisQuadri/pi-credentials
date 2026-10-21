import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { BuildSpec } from "pi-compiled";
import { helperBuild, prepareHelper } from "./helper.ts";

function checkout(): BuildSpec {
	const root = mkdtempSync(join(tmpdir(), "pi-credentials-gate-"));
	writeFileSync(join(root, "source.txt"), "v1\n");
	writeFileSync(join(root, ".gitignore"), "bin/\n.swiftpm/\n");
	for (const args of [["init", "-q"], ["add", "."], ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init"]]) execFileSync("git", ["-C", root, ...args]);
	return { packageRoot: root, binary: "bin/helper", buildCommand: ["/bin/sh", "-c", "echo '[1/2] Compiling helper'; mkdir -p bin && touch bin/helper && chmod +x bin/helper; echo '[2/2] Linking helper'"], inputs: ["source.txt"], overrideEnv: "PI_CREDENTIALS_GATE_TEST" };
}

function context(isInteractive = true) {
	const widgets: (string[] | undefined)[] = [];
	const asked: string[] = [];
	const ctx = { hasUI: isInteractive, ui: { confirm: async (title: string) => { asked.push(title); return true; }, notify: () => undefined, setWidget: (_key: string, lines: string[] | undefined) => { widgets.push(lines); } } } as never;
	return { ctx, widgets, asked };
}

test("the helper builds after install without asking, shows its progress, and refuses unchecked source", async () => {
	assert.equal(helperBuild.isUpstreamRequired, true);
	let build = checkout();
	writeFileSync(join(build.packageRoot, "source.txt"), "tampered\n");
	await assert.rejects(prepareHelper(context().ctx, build), { code: "helper-build-refused" });

	build = checkout();
	mkdirSync(join(build.packageRoot, ".swiftpm"));
	await assert.rejects(prepareHelper(context().ctx, build), (error: Error & { code: string }) => error.code === "helper-build-refused" && /\.swiftpm/.test(error.message));
	rmSync(join(build.packageRoot, ".swiftpm"), { recursive: true });

	const interactive = context();
	await prepareHelper(interactive.ctx, build);
	assert.equal(interactive.asked.length, 0);
	assert.equal(existsSync(join(build.packageRoot, "bin/helper")), true);
	assert.ok(interactive.widgets.some((lines) => lines?.[0]?.includes("1/2 Compiling helper")));
	assert.equal(interactive.widgets.at(-1), undefined);

	rmSync(join(build.packageRoot, "bin/helper"));
	const headless = context(false);
	await prepareHelper(headless.ctx, build);
	assert.equal(existsSync(join(build.packageRoot, "bin/helper")), true);
	assert.equal(headless.widgets.length, 0);

	const again = context();
	await prepareHelper(again.ctx, build);
	assert.equal(again.widgets.length, 0);
});

test("only the fetched upstream commit is built, and a failed build clears its progress bar", async () => {
	const local = context();
	await assert.rejects(prepareHelper(local.ctx, { ...checkout(), isUpstreamRequired: true }), (error: Error & { code: string }) => error.code === "helper-build-refused" && /upstream/.test(error.message));
	assert.equal(local.widgets.length, 0);

	const failing = context();
	await assert.rejects(prepareHelper(failing.ctx, { ...checkout(), buildCommand: ["/bin/sh", "-c", "echo '[1/2] Compiling helper'; exit 1"] }), { code: "build-failed" });
	assert.ok(failing.widgets.some((lines) => lines?.[0]?.includes("1/2 Compiling helper")));
	assert.equal(failing.widgets.at(-1), undefined);
});

test("a helper override must be an absolute path to an executable, so a relative name is never run", async () => {
	const build = checkout();
	process.env.PI_CREDENTIALS_GATE_TEST = "helper";
	await assert.rejects(prepareHelper(context().ctx, build), { code: "build-failed" });
	process.env.PI_CREDENTIALS_GATE_TEST = "/usr/bin/true";
	await prepareHelper(context().ctx, build);
	delete process.env.PI_CREDENTIALS_GATE_TEST;
});
