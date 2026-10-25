import assert from "node:assert/strict";
import { test } from "node:test";
import { createCredentialRedactionProvider, credentialRedactionDiscoveryEvent, type CredentialRedactionRequestV1, type CredentialRedactionResultV1, type CredentialRedactionServiceV1 } from "./redaction-service.ts";

const request = (pieces: readonly string[] = ["synthetic text"]): CredentialRedactionRequestV1 => ({ version: 1, requestID: "fixture-1", pieces });
const options = () => ({ signal: new AbortController().signal });
const blocked = (code: string, requestID = "fixture-1") => ({ status: "blocked", requestID, code });

function deferred<T>() {
	let resolve!: (value: T) => void;
	const promise = new Promise<T>((done) => { resolve = done; });
	return { promise, resolve };
}

function provider(redactor: (pieces: string[], signal: AbortSignal) => Promise<unknown> = async () => undefined) {
	const result = createCredentialRedactionProvider(redactor);
	result.initialize(Promise.resolve(true));
	return result;
}

test("createCredentialRedactionProvider explicitly checks unchanged text and snapshots mutable input", async () => {
	const readiness = deferred<boolean>();
	const gate = createCredentialRedactionProvider(async (pieces) => { pieces[0] = "mutated fixture"; return undefined; });
	gate.initialize(readiness.promise);
	const pieces = ["clean 😀", "binary\u0000text"];
	const pending = gate.service.redact(request(pieces), options());
	pieces[0] = "caller mutation";
	readiness.resolve(true);
	assert.deepEqual(await pending, { status: "checked", requestID: "fixture-1", policy: "pi-credentials/redact-v1", pieces: ["clean 😀", "binary\u0000text"] });
	assert.deepEqual(await gate.service.redact(request([]), options()), { status: "checked", requestID: "fixture-1", policy: "pi-credentials/redact-v1", pieces: [] });
});

test("createCredentialRedactionProvider preserves synthetic known and unknown replacements in multiple pieces", async () => {
	const gate = provider(async (pieces) => ({ pieces: pieces.map((piece) => piece.replaceAll("FIXTURE_KNOWN", "[cred:fixture]").replaceAll("FIXTURE_UNKNOWN", "[cred:unknown-fixture]")), unavailable: [] }));
	const result = await gate.service.redact(request(["before FIXTURE_KNOWN after", "FIXTURE_UNKNOWN and FIXTURE_KNOWN"]), options());
	assert.deepEqual(result, { status: "checked", requestID: "fixture-1", policy: "pi-credentials/redact-v1", pieces: ["before [cred:fixture] after", "[cred:unknown-fixture] and [cred:fixture]"] });
});

test("createCredentialRedactionProvider withholds native Markdown escaped underscore and hyphen secrets without changing clean bytes", async () => {
	const calls: string[][] = [];
	const gate = provider(async (pieces) => {
		calls.push(pieces);
		return { pieces: pieces.map((piece) => piece.replaceAll("REGISTERED_CLAIM_SECRET", "[cred:fixture]").replaceAll("REGISTERED-CLAIM-SECRET", "[cred:fixture]")), unavailable: [] };
	});
	const pieces = [String.raw`old REGISTERED\_CLAIM\_SECRET [source: synthetic]`, String.raw`old REGISTERED\-CLAIM\-SECRET`, String.raw`clean\_text and clean\-text`, "plain text", "raw REGISTERED_CLAIM_SECRET"];
	assert.deepEqual(await gate.service.redact(request(pieces), options()), {
		status: "checked", requestID: "fixture-1", policy: "pi-credentials/redact-v1",
		pieces: ["[cred:redacted]", "[cred:redacted]", pieces[2], pieces[3], "raw [cred:fixture]"],
	});
	assert.deepEqual(calls, [pieces, ["old REGISTERED_CLAIM_SECRET [source: synthetic]", "old REGISTERED-CLAIM-SECRET", "clean_text and clean-text"]]);
});

test("createCredentialRedactionProvider decodes native entities before backslashes exactly once and preserves literal punctuation", async () => {
	const calls: string[][] = [];
	const gate = provider(async (pieces) => {
		calls.push(pieces);
		return { pieces: pieces.map((piece) => piece.replaceAll("&#32;ENTITY_KEY", "[cred:fixture]").replaceAll(String.raw`PATH\_SECRET`, "[cred:fixture]")), unavailable: [] };
	});
	const punctuation = "\\\\\\`\\*\\_\\{\\}\\[\\]\\<\\>\\#\\+\\-\\!\\|\\~\\&\\=";
	const pieces = [String.raw`\&#32;ENTITY\_KEY`, "&#32;ENTITY\\_KEY", String.raw`PATH\\\_SECRET`, punctuation, "&#32;&#32;clean\\_text\n123\\. list\n9\\) list\n1234567890\\. literal"];
	assert.deepEqual(await gate.service.redact(request(pieces), options()), {
		status: "checked", requestID: "fixture-1", policy: "pi-credentials/redact-v1", pieces: ["[cred:redacted]", pieces[1], "[cred:redacted]", pieces[3], pieces[4]],
	});
	assert.deepEqual(calls[1], ["&#32;ENTITY_KEY", " ENTITY_KEY", String.raw`PATH\_SECRET`, "\\`*_{}[]<>#+-!|~&=", "  clean_text\n123. list\n9) list\n1234567890\\. literal"]);
});

test("createCredentialRedactionProvider blocks unavailable and invalid decoded checks instead of accepting checked originals", async () => {
	for (const [output, code] of [
		[{ pieces: ["clean"], unavailable: ["FIXTURE_RAW_SENTINEL"] }, "unavailable"],
		[null, "invalid-output"], [{ pieces: [], unavailable: [] }, "invalid-output"],
		[{ pieces: ["clean", "extra"], unavailable: [] }, "invalid-output"],
		[{ pieces: ["\uD800"], unavailable: [] }, "invalid-output"],
	] as const) {
		let calls = 0;
		const gate = provider(async () => { calls += 1; return calls === 1 ? undefined : output; });
		assert.deepEqual(await gate.service.redact(request([String.raw`escaped\_text`]), options()), blocked(code));
		assert.equal(calls, 2);
	}
});

test("createCredentialRedactionProvider aborts decoded checks on cancellation and unload without accepting late success", async () => {
	for (const interruption of ["cancel", "unload"] as const) {
		const completion = deferred<unknown>();
		const started = deferred<AbortSignal>();
		let calls = 0;
		const gate = provider(async (_pieces, signal) => {
			calls += 1;
			if (calls === 1) return undefined;
			started.resolve(signal);
			return completion.promise;
		});
		const caller = new AbortController();
		const pending = gate.service.redact(request([String.raw`escaped\_text`]), { signal: caller.signal });
		const signal = await started.promise;
		if (interruption === "cancel") caller.abort();
		else gate.dispose();
		const result = await pending;
		assert.deepEqual(result, blocked(interruption === "cancel" ? "cancelled" : "not-ready"));
		assert.equal(signal.aborted, true);
		completion.resolve(undefined);
		await Promise.resolve();
		assert.deepEqual(await pending, result);
	}
});

test("createCredentialRedactionProvider shares the original deadline and per-call input bounds with decoded checks", async (t) => {
	let now = 0;
	t.mock.method(performance, "now", () => now);
	let calls = 0;
	const gate = provider(async (pieces) => {
		calls += 1;
		assert.ok(pieces.length <= 1_000);
		assert.ok(pieces.every((piece) => Buffer.byteLength(piece) <= 1_048_576));
		assert.ok(pieces.reduce((total, piece) => total + Buffer.byteLength(piece), 0) <= 4_194_304);
		now = calls === 1 ? 6_000 : 10_001;
		return undefined;
	});
	assert.deepEqual(await gate.service.redact(request(new Array(4).fill(String.raw`\_`.repeat(524_288))), options()), blocked("timeout"));
	assert.equal(calls, 2);
});

test("createCredentialRedactionProvider refuses malformed requests and UTF8 input limits before redaction", async () => {
	let calls = 0;
	const gate = provider(async () => { calls += 1; });
	const maximum = "x".repeat(1_048_576);
	for (const value of [null, [], {}, { ...request(), version: 2 }, { ...request(), requestID: "" }, { ...request(), requestID: "x".repeat(129) },
		request([1 as never]), request(new Array(1)), request(["\uD800"]), request(["\uDC00"]), request(new Array(1_001).fill("")),
		request([maximum + "x"]), request(["é".repeat(524_289)]), request([maximum, maximum, maximum, maximum, "x"])]) {
		const result = await gate.service.redact(value as CredentialRedactionRequestV1, options());
		assert.equal(result.status, "blocked");
		if (result.status === "blocked") assert.equal(result.code, "invalid-input");
	}
	assert.deepEqual(await gate.service.redact(request(), {} as never), blocked("invalid-input"));
	assert.equal(calls, 0);
	assert.equal((await gate.service.redact(request([maximum, maximum, maximum, maximum]), options())).status, "checked");
	assert.equal((await gate.service.redact(request(new Array(1_000).fill("")), options())).status, "checked");
});

test("createCredentialRedactionProvider withholds malformed output and unavailable checks even with clean output", async () => {
	const maximum = "x".repeat(8_388_608);
	for (const output of [null, [], {}, { pieces: ["clean"], unavailable: "fixture" }, { pieces: ["clean"], unavailable: [1] },
		{ pieces: [], unavailable: [] }, { pieces: ["clean", "extra"], unavailable: [] }, { pieces: [1], unavailable: [] },
		{ pieces: new Array(1), unavailable: [] }, { pieces: ["\uD800"], unavailable: [] }, { pieces: [maximum + "x"], unavailable: [] },
		{ pieces: ["é".repeat(4_194_305)], unavailable: [] }]) {
		assert.deepEqual(await provider(async () => output).service.redact(request(), options()), blocked("invalid-output"));
	}
	assert.deepEqual(await provider(async () => ({ pieces: ["clean"], unavailable: ["FIXTURE_RAW_SENTINEL"] })).service.redact(request(), options()), blocked("unavailable"));
	assert.equal((await provider(async () => ({ pieces: [maximum], unavailable: [] })).service.redact(request(), options())).status, "checked");
	assert.deepEqual(await provider(async () => ({ pieces: [maximum, "x"], unavailable: [] })).service.redact(request(["a", "b"]), options()), blocked("invalid-output"));
});

test("createCredentialRedactionProvider cannot confuse initial readiness or failed startup with success", async () => {
	let calls = 0;
	const gate = createCredentialRedactionProvider(async () => { calls += 1; });
	assert.deepEqual(await gate.service.redact(request(), options()), blocked("not-ready"));
	gate.initialize(Promise.resolve(false));
	assert.deepEqual(await gate.service.redact(request(), options()), blocked("not-ready"));
	gate.initialize(Promise.reject(new Error("FIXTURE_RAW_SENTINEL")));
	assert.deepEqual(await gate.service.redact(request(), options()), blocked("not-ready"));
	assert.equal(calls, 0);
});

test("createCredentialRedactionProvider revokes pending and retained capabilities on unload and reinitialization", async () => {
	const readiness = deferred<boolean>();
	const gate = createCredentialRedactionProvider(async () => undefined);
	gate.initialize(readiness.promise);
	const waiting = gate.service.redact(request(), options());
	gate.initialize(Promise.resolve(true));
	assert.deepEqual(await waiting, blocked("not-ready"));
	readiness.resolve(true);
	assert.equal((await gate.service.redact(request(), options())).status, "checked");
	const completion = deferred<unknown>();
	const started = deferred<AbortSignal>();
	const active = provider(async (_pieces, signal) => { started.resolve(signal); return completion.promise; });
	const pending = active.service.redact(request(), options());
	const signal = await started.promise;
	active.dispose();
	assert.deepEqual(await pending, blocked("not-ready"));
	assert.equal(signal.aborted, true);
	completion.resolve(undefined);
	active.initialize(Promise.resolve(true));
	assert.deepEqual(await active.service.redact(request(), options()), blocked("not-ready"));
	assert.equal((await provider().service.redact(request(), options())).status, "checked");
});

test("createCredentialRedactionProvider cancels readiness and active work without accepting late results", async () => {
	let calls = 0;
	const waiting = provider(async () => { calls += 1; });
	const readiness = deferred<boolean>();
	waiting.initialize(readiness.promise);
	const caller = new AbortController();
	const pending = waiting.service.redact(request(), { signal: caller.signal });
	caller.abort(new Error("FIXTURE_RAW_SENTINEL"));
	assert.deepEqual(await pending, blocked("cancelled"));
	readiness.resolve(true);
	await Promise.resolve();
	assert.equal(calls, 0);
	assert.deepEqual(await waiting.service.redact(request(), { signal: caller.signal }), blocked("cancelled"));
	const completion = deferred<unknown>();
	const started = deferred<AbortSignal>();
	const gate = provider(async (_pieces, signal) => { started.resolve(signal); return completion.promise; });
	const activeCaller = new AbortController();
	const active = gate.service.redact(request(), { signal: activeCaller.signal });
	const workSignal = await started.promise;
	activeCaller.abort();
	const result = await active;
	assert.deepEqual(result, blocked("cancelled"));
	assert.equal(workSignal.aborted, true);
	completion.resolve({ pieces: ["FIXTURE_RAW_SENTINEL"], unavailable: [] });
	await Promise.resolve();
	assert.deepEqual(await active, result);
});

test("createCredentialRedactionProvider includes readiness in its ten second deadline and ignores late completion", async () => {
	const readiness = deferred<boolean>();
	let calls = 0;
	const waiting = createCredentialRedactionProvider(async () => { calls += 1; });
	waiting.initialize(readiness.promise);
	const completion = deferred<unknown>();
	const started = deferred<AbortSignal>();
	const active = provider(async (_pieces, signal) => { started.resolve(signal); return completion.promise; });
	const waitingResult = waiting.service.redact(request(), options());
	const activeResult = active.service.redact(request(), options());
	const workSignal = await started.promise;
	assert.deepEqual(await waitingResult, blocked("timeout"));
	assert.deepEqual(await activeResult, blocked("timeout"));
	assert.equal(workSignal.aborted, true);
	readiness.resolve(true);
	completion.resolve(undefined);
	await Promise.resolve();
	assert.equal(calls, 0);
	assert.deepEqual(await activeResult, blocked("timeout"));
});

test("createCredentialRedactionProvider rejects completions past the deadline even before the timer fires", async (t) => {
	let now = 0;
	t.mock.method(performance, "now", () => now);
	const gate = provider(async () => { now = 10_001; return undefined; });
	assert.deepEqual(await gate.service.redact(request(), options()), blocked("timeout"));
});

test("createCredentialRedactionProvider emits no raw sentinel or exception text in failures or logs", async (t) => {
	const logs: unknown[] = [];
	for (const method of ["log", "error", "warn"] as const) t.mock.method(console, method, (...args: unknown[]) => { logs.push(args); });
	const sentinel = "FIXTURE_RAW_SENTINEL";
	const results: CredentialRedactionResultV1[] = [];
	results.push(await provider(async () => { throw new Error(sentinel); }).service.redact(request([sentinel]), options()));
	results.push(await provider(async () => ({ pieces: [sentinel], unavailable: [sentinel] })).service.redact(request([sentinel]), options()));
	results.push(await provider(async () => ({ pieces: [sentinel, sentinel], unavailable: [] })).service.redact(request([sentinel]), options()));
	assert.deepEqual(results, [blocked("failed"), blocked("unavailable"), blocked("invalid-output")]);
	assert.doesNotMatch(JSON.stringify({ results, logs }), new RegExp(sentinel));
	assert.deepEqual(logs, []);
});

test("credentialRedactionDiscoveryEvent only offers a capability synchronously without text and revokes discovery on unload", () => {
	assert.equal(credentialRedactionDiscoveryEvent, "pi-credentials:redaction-service:v1");
	const gate = provider();
	const services: CredentialRedactionServiceV1[] = [];
	const discovery = { version: 1, signal: new AbortController().signal, provide: (service: CredentialRedactionServiceV1) => { services.push(service); } };
	assert.deepEqual(Object.keys(discovery), ["version", "signal", "provide"]);
	for (const payload of [undefined, {}, { ...discovery, version: 2 }, { ...discovery, signal: AbortSignal.abort() }, { ...discovery, pieces: ["FIXTURE_RAW_SENTINEL"] }]) gate.discover(payload);
	assert.equal(services.length, 0);
	gate.discover(discovery);
	assert.deepEqual(services, [gate.service]);
	assert.deepEqual(Object.keys(services[0]), ["version", "redact"]);
	assert.equal(services[0].version, 1);
	assert.doesNotThrow(() => gate.discover({ ...discovery, provide: () => { throw new Error("FIXTURE_RAW_SENTINEL"); } }));
	gate.dispose();
	gate.discover(discovery);
	assert.equal(services.length, 1);
});
