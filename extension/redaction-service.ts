export const credentialRedactionDiscoveryEvent = "pi-credentials:redaction-service:v1";

export interface CredentialRedactionRequestV1 {
	version: 1;
	requestID: string;
	pieces: readonly string[];
}

export type CredentialRedactionBlockedCode = "not-ready" | "unavailable" | "timeout" | "cancelled" | "invalid-input" | "invalid-output" | "failed";

export type CredentialRedactionResultV1 =
	| { status: "checked"; requestID: string; policy: "pi-credentials/redact-v1"; pieces: string[] }
	| { status: "blocked"; requestID: string; code: CredentialRedactionBlockedCode };

export interface CredentialRedactionServiceV1 {
	readonly version: 1;
	redact(request: CredentialRedactionRequestV1, options: { signal: AbortSignal }): Promise<CredentialRedactionResultV1>;
}

export interface CredentialRedactionDiscoveryV1 {
	version: 1;
	signal: AbortSignal;
	provide(service: CredentialRedactionServiceV1): void;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isPieces(value: unknown, totalLimit: number, pieceLimit = totalLimit): value is string[] {
	if (!Array.isArray(value) || value.length > 1_000) return false;
	let total = 0;
	for (const piece of value) {
		if (typeof piece !== "string" || piece.length > pieceLimit || /[\uD800-\uDFFF]/u.test(piece)) return false;
		const bytes = Buffer.byteLength(piece, "utf8");
		if (bytes > pieceLimit) return false;
		total += bytes;
		if (total > totalLimit) return false;
	}
	return true;
}

function decodeNativeMarkdown(piece: string): string {
	return piece.replace(/^(?:&#32;)+/gm, (spaces) => " ".repeat(spaces.length / 5))
		.replace(/^([0-9]{1,9})\\([.)]) /gm, "$1$2 ")
		.replace(/\\([\\`*_{}\[\]<>#+\-!|~&=])/g, "$1");
}

export function createCredentialRedactionProvider(redactPieces: (pieces: string[], signal: AbortSignal) => Promise<unknown>) {
	let startup: Promise<boolean> | undefined;
	let lifetime = new AbortController();
	let isDisposed = false;

	const service: CredentialRedactionServiceV1 = Object.freeze({
		version: 1,
		async redact(request: CredentialRedactionRequestV1, options: { signal: AbortSignal }): Promise<CredentialRedactionResultV1> {
			const deadline = performance.now() + 10_000;
			let requestID = "";
			try {
				if (!isRecord(request) || typeof request.requestID !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(request.requestID)) {
					return { status: "blocked", requestID, code: "invalid-input" };
				}
				requestID = request.requestID;
				if (request.version !== 1 || !isPieces(request.pieces, 4_194_304, 1_048_576) || !(options?.signal instanceof AbortSignal)) {
					return { status: "blocked", requestID, code: "invalid-input" };
				}
				const pieces = [...request.pieces];
				const readiness = startup;
				const session = lifetime.signal;
				if (options.signal.aborted) return { status: "blocked", requestID, code: "cancelled" };
				if (isDisposed || !readiness) return { status: "blocked", requestID, code: "not-ready" };
				return await new Promise<CredentialRedactionResultV1>((resolve) => {
					let isSettled = false;
					const work = new AbortController();
					const finish = (result: CredentialRedactionResultV1) => {
						if (isSettled) return;
						const stopped = interruption();
						if (result.status === "checked" && stopped) result = { status: "blocked", requestID, code: stopped };
						isSettled = true;
						clearTimeout(timer);
						options.signal.removeEventListener("abort", cancel);
						session.removeEventListener("abort", unload);
						work.abort();
						resolve(result);
					};
					const block = (code: CredentialRedactionBlockedCode) => finish({ status: "blocked", requestID, code });
					const cancel = () => block("cancelled");
					const unload = () => block("not-ready");
					const timer = setTimeout(() => block("timeout"), Math.max(0, deadline - performance.now()));
					options.signal.addEventListener("abort", cancel, { once: true });
					session.addEventListener("abort", unload, { once: true });
					const interruption = (): CredentialRedactionBlockedCode | undefined => {
						if (options.signal.aborted) return "cancelled";
						if (session.aborted || isDisposed) return "not-ready";
						if (performance.now() >= deadline) return "timeout";
						return undefined;
					};
					void (async () => {
						const isReady = await readiness;
						if (isSettled) return;
						const before = interruption();
						if (before) return block(before);
						if (!isReady) return block("not-ready");
						const decoded = pieces.map(decodeNativeMarkdown);
						const changedIndices = pieces.flatMap((piece, index) => piece === decoded[index] ? [] : [index]);
						let checkedPieces = pieces;
						for (const [phase, input] of [pieces, changedIndices.map((index) => decoded[index])].entries()) {
							if (phase === 1 && input.length === 0) break;
							const beforePhase = interruption();
							if (beforePhase) return block(beforePhase);
							const result = await redactPieces([...input], work.signal);
							if (isSettled) return;
							const after = interruption();
							if (after) return block(after);
							let output = input;
							if (result !== undefined) {
								if (!isRecord(result) || !Array.isArray(result.unavailable) || !result.unavailable.every((item) => typeof item === "string")) return block("invalid-output");
								if (result.unavailable.length) return block("unavailable");
								if (!isPieces(result.pieces, 8_388_608) || result.pieces.length !== input.length) return block("invalid-output");
								output = result.pieces;
							}
							if (phase === 0) checkedPieces = [...output];
							else for (const [index, piece] of output.entries()) {
								if (piece !== input[index]) checkedPieces[changedIndices[index]] = "[cred:redacted]";
							}
						}
						if (!isPieces(checkedPieces, 8_388_608)) return block("invalid-output");
						finish({ status: "checked", requestID, policy: "pi-credentials/redact-v1", pieces: checkedPieces });
					})().catch(() => block(interruption() ?? "failed"));
				});
			} catch {
				return { status: "blocked", requestID, code: "failed" };
			}
		},
	});

	return {
		service,
		initialize(readiness: Promise<boolean>) {
			lifetime.abort();
			lifetime = new AbortController();
			startup = readiness.then((isReady) => isReady === true, () => false);
		},
		dispose() {
			isDisposed = true;
			lifetime.abort();
		},
		discover(payload: unknown) {
			try {
				if (isDisposed || !isRecord(payload) || Object.keys(payload).length !== 3 || payload.version !== 1
					|| !(payload.signal instanceof AbortSignal) || payload.signal.aborted || typeof payload.provide !== "function") return;
				payload.provide(service);
			} catch {}
		},
	};
}
