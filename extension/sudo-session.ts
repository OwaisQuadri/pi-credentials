import { spawn, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import { HelperError, helperPath, parseHelperOutput } from "./helper.ts";

export class SudoSession {
	private child?: ChildProcess;
	private pending?: { resolve: (result: unknown) => void; reject: (error: Error) => void };
	private queue: Promise<unknown> = Promise.resolve();
	private isClosed = false;

	call<T>(command: "sudo" | "ssh-sudo", input: Record<string, unknown>, signal?: AbortSignal): Promise<T> {
		const cancel = () => this.cancel(signal);
		signal?.addEventListener("abort", cancel, { once: true });
		if (signal?.aborted) cancel();
		const result = this.queue.then(() => {
			if (signal?.aborted) throw this.cancel(signal);
			return this.send(command, input);
		});
		this.queue = result.catch(() => undefined);
		return result.finally(() => signal?.removeEventListener("abort", cancel)) as Promise<T>;
	}

	cancel(signal?: AbortSignal): HelperError {
		const error = new HelperError(
			(signal?.reason as Error | undefined)?.name === "TimeoutError" ? "timeout" : "aborted",
			"The credential operation stopped. Root session approval was cleared.",
		);
		this.stop(error);
		return error;
	}

	close(): void {
		this.isClosed = true;
		this.stop(new HelperError("aborted", "The Pi session ended. Root approval was cleared."));
	}

	private stop(error: Error): void {
		const child = this.child;
		this.child = undefined;
		const pending = this.pending;
		this.pending = undefined;
		pending?.reject(error);
		child?.stdin?.end();
		child?.kill("SIGTERM");
	}

	private start(): Promise<ChildProcess> {
		const child = spawn(helperPath, ["sudo-session"], { stdio: ["pipe", "pipe", "ignore"] });
		this.child = child;
		const lines = createInterface({ input: child.stdout });
		const fail = (error: Error) => { if (this.child === child) this.stop(error); };
		lines.on("line", (line) => {
			if (this.child !== child) return;
			const pending = this.pending;
			this.pending = undefined;
			if (!pending) return fail(new HelperError("helper-output", "The root helper returned an unexpected response."));
			try { pending.resolve(parseHelperOutput(line)); }
			catch (error) {
				pending.reject(error as Error);
				if (error instanceof HelperError && error.code === "helper-output") fail(error);
			}
		});
		child.stdin.on("error", () => fail(new HelperError("helper-unavailable", "The root helper connection closed.")));
		child.on("error", (error) => fail(new HelperError("helper-unavailable", `The root helper failed to start (${error.message}).`)));
		child.on("close", () => {
			lines.close();
			fail(new HelperError("helper-unavailable", "The root helper exited. Its session approval was cleared."));
		});
		const incompatible = new HelperError("helper-incompatible", "The root helper does not support session approval. Rebuild it with scripts/build.zsh. No root command was submitted.");
		const timeout = setTimeout(() => { if (this.child === child) this.stop(incompatible); }, 5_000);
		return new Promise<ChildProcess>((resolve, reject) => {
			this.pending = {
				resolve: (reply) => {
					if ((reply as { protocol?: unknown }).protocol === 1) return resolve(child);
					this.stop(incompatible);
					reject(incompatible);
				},
				reject,
			};
		}).finally(() => clearTimeout(timeout));
	}

	private async send(command: string, input: Record<string, unknown>): Promise<unknown> {
		if (this.isClosed) throw new HelperError("aborted", "The Pi session ended. Root approval was cleared.");
		const child = this.child ?? await this.start();
		if (this.child !== child) throw new HelperError("aborted", "The root helper stopped before the command was submitted.");
		return new Promise((resolve, reject) => {
			this.pending = { resolve, reject };
			child.stdin!.write(`${JSON.stringify({ command, input })}\n`);
		});
	}
}
