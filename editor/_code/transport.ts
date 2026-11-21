import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { digest, text } from "./source";

export type RecordValue = Record<string, unknown>;
export function object(value: unknown): RecordValue {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Expected a protocol object.");
    return value as RecordValue;
}
export type Frame = {
    protocol_version: number;
    request_id: string;
    state_ref: string;
    context_ref: string | null;
    actual_source_ref: string;
    selected_source_ref: string | null;
    source_freshness: "FRESH" | "STALE" | "MISSING";
    limitations: string[];
    result: { kind: string; data: unknown } | null;
    error: { code: string; message: string; candidates?: string[] } | null;
};

const REQUEST_LIMIT = 65_536;
const RESPONSE_LIMIT = 1_048_576;
const ACTIVE_LIMIT = 8;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function canonical(value: unknown, depth = 0): string {
    if (depth > 64) throw new Error("Protocol nesting limit exceeded.");
    if (Array.isArray(value)) return "[" + value.map(entry => canonical(entry, depth + 1)).join(",") + "]";
    if (value !== null && typeof value === "object") {
        const dictionary = object(value);
        return "{" + Object.keys(dictionary).sort().map(key =>
            JSON.stringify(key) + ":" + canonical(dictionary[key], depth + 1)).join(",") + "}";
    }
    return JSON.stringify(value);
}

export function decodeFrame(bytes: Uint8Array): Frame {
    const raw = utf8.decode(bytes);
    const value = object(JSON.parse(raw));
    if (canonical(value) !== raw) throw new Error("Malformed or noncanonical Fortress response.");
    const version = value.protocol_version;
    const identity = value.state_ref;
    if (typeof version !== "number" || ![1, 2, 3, 4, 5].includes(version) ||
        value.$schema !== `urn:fortress:protocol:v${version}:query-response` ||
        typeof value.request_id !== "string" || !digest(identity) ||
        !digest(value.actual_source_ref) || !(value.context_ref === null || digest(value.context_ref)) ||
        !(value.selected_source_ref === null || digest(value.selected_source_ref)) ||
        !["FRESH", "STALE", "MISSING"].includes(String(value.source_freshness)) ||
        !Array.isArray(value.limitations) || !value.limitations.every(entry => typeof entry === "string") ||
        (value.result === null) === (value.error === null)) throw new Error("Invalid Fortress response envelope.");
    if (value.result !== null && typeof object(value.result).kind !== "string") throw new Error("Invalid result family.");
    if (value.error !== null) {
        const error = object(value.error);
        if (typeof error.code !== "string" || typeof error.message !== "string") throw new Error("Invalid structured error.");
    }
    return value as Frame;
}

export class Frames {
    private readonly queue = Buffer.alloc(RESPONSE_LIMIT);
    private length = 0;
    push(data: Buffer, receive: (frame: Frame) => void) {
        for (let start = 0; start < data.length;) {
            const newline = data.indexOf(10, start);
            const end = newline < 0 ? data.length : newline;
            const size = end - start;
            if (size + this.length > this.queue.length) throw new Error("Fortress response exceeds the byte limit.");
            data.copy(this.queue, this.length, start, end);
            this.length += size;
            if (newline < 0) break;
            const frame = decodeFrame(this.queue.subarray(0, this.length));
            this.length = 0;
            start = end + 1;
            receive(frame);
        }
    }
    finish() {
        if (this.length) throw new Error("Fortress closed mid-frame.");
    }
}

export interface Launch { executable: string; cwd: string }
function start(launch: Launch, args: string[]) {
    return spawn(launch.executable, args, {
        cwd: launch.cwd, stdio: "pipe", windowsHide: true, shell: false
    });
}

export class FortressError extends Error {
    constructor(readonly code: string, detail: string, readonly candidates: string[] = []) {
        super(text(detail, 1200));
    }
}
const cancelled = () => new FortressError("CANCELLED", "The request was cancelled.");
type Pending = {
    version: number;
    method: string;
    resolve: (value: Frame) => void;
    reject: (reason: Error) => void;
    release: () => void;
};

export class Stdio {
    private readonly child: ChildProcessWithoutNullStreams;
    private readonly pending = new Map<string, Pending>();
    private readonly frames = new Frames();
    private readonly closed: Promise<void>;
    private phase: "open" | "closing" | "closed" = "open";
    private sequence = 0;
    private stderr = "";
    private version = 1;
    private requestLimit = REQUEST_LIMIT;
    private bound?: Frame;
    private disposal?: Promise<void>;
    private methods = new Set<string>();
    metadata: RecordValue = {};
    pageSize = 30;

    constructor(launch: Launch, args: string[], private readonly deadline = 30_000) {
        this.child = start(launch, args);
        this.closed = new Promise(resolve => this.child.once("close", () => {
            let cause = this.stderr || "Fortress closed its stdio service.";
            try { this.frames.finish(); } catch (error) { cause = (error as Error).message; }
            this.phase = "closed";
            this.failAll(new FortressError("SERVICE_CLOSED", cause));
            resolve();
        }));
        this.child.on("error", error => { void this.stop(new FortressError("START_FAILED", error.message)); });
        this.child.stdin.on("error", error => { void this.stop(new FortressError("PIPE_FAILED", error.message)); });
        this.child.stderr.on("data", (chunk: Buffer) => {
            if (this.stderr.length < 2048) this.stderr += text(chunk.subarray(0, 2048).toString(), 2048 - this.stderr.length);
        });
        this.child.stdout.on("data", (chunk: Buffer) => {
            if (this.phase !== "open") return;
            try { this.frames.push(chunk, frame => this.receive(frame)); }
            catch (error) { void this.stop(new FortressError("INVALID_RESPONSE", (error as Error).message)); }
        });
    }

    supports(method: string) { return this.methods.has(method); }

    async negotiate(signal?: AbortSignal): Promise<Frame> {
        const discovery = await this.send(1, "protocol", {}, signal);
        const advertised = object(discovery.result?.data);
        const versions = advertised.protocol_versions;
        if (!Array.isArray(versions)) throw new Error("No supported Fortress protocol was advertised.");
        const selected = [5, 4, 3, 2, 1].find(version => versions.includes(version));
        if (!selected) throw new Error("Fortress and the editor share no supported protocol version.");
        this.version = selected;
        const reply = selected === 1 ? discovery : await this.send(selected, "protocol", {}, signal);
        const metadata = object(reply.result?.data);
        const methods = metadata.methods;
        if (reply.result?.kind !== "PROTOCOL" || !Array.isArray(methods) || metadata.mutation !== false ||
            !methods.every(value => typeof value === "string") || !methods.includes("status")) {
            throw new Error("Incompatible read-only Fortress service.");
        }
        const maxPage = metadata.max_page_size;
        const maxRequest = metadata.max_request_bytes;
        if (typeof maxPage !== "number" || !Number.isSafeInteger(maxPage) || maxPage < 1 ||
            typeof maxRequest !== "number" || !Number.isSafeInteger(maxRequest) || maxRequest < 1) {
            throw new Error("Invalid service limits.");
        }
        this.pageSize = Math.min(30, maxPage);
        this.requestLimit = Math.min(REQUEST_LIMIT, maxRequest);
        this.metadata = metadata;
        this.methods = new Set(methods);
        this.bound = reply;
        return this.call("status", {}, signal);
    }

    call(method: string, parameters: RecordValue = {}, signal?: AbortSignal) {
        if (!this.supports(method)) return Promise.reject(new FortressError("UNAVAILABLE", "This service does not advertise " + method + "."));
        return this.send(this.version, method, parameters, signal);
    }

    private send(version: number, method: string, params: RecordValue, signal?: AbortSignal): Promise<Frame> {
        const control = method === "cancel";
        const capacity = control ? ACTIVE_LIMIT * 2 : ACTIVE_LIMIT;
        if (this.phase !== "open") return Promise.reject(new FortressError("SERVICE_CLOSED", "Restart Fortress inspection."));
        if (signal?.aborted) return Promise.reject(cancelled());
        if (this.pending.size >= capacity || this.child.stdin.writableLength > REQUEST_LIMIT) {
            return Promise.reject(new FortressError("RESOURCE_LIMIT", "Too many Fortress requests are active."));
        }
        const id = String(++this.sequence);
        const frame = JSON.stringify({
            protocol_version: version, request_id: id, method, parameters: params,
            state_ref: this.bound?.state_ref ?? null, context_ref: this.bound?.context_ref ?? null
        });
        if (Buffer.byteLength(frame) > this.requestLimit) return Promise.reject(new FortressError("RESOURCE_LIMIT", "Fortress request exceeds the byte limit."));
        return new Promise((resolve, reject) => {
            const onAbort = () => {
                reject(cancelled());
                if (this.supports("cancel")) {
                    void this.send(version, "cancel", { request_id: id }).catch(() => this.stop(cancelled()));
                } else {
                    void this.stop(cancelled());
                }
            };
            const timer = setTimeout(() => {
                void this.stop(new FortressError("TIMEOUT", "Fortress did not complete the bounded request."));
            }, this.deadline);
            this.pending.set(id, {
                version, method, resolve, reject,
                release: () => { clearTimeout(timer); signal?.removeEventListener("abort", onAbort); }
            });
            signal?.addEventListener("abort", onAbort, { once: true });
            this.child.stdin.write(frame + "\n");
        });
    }

    private receive(frame: Frame) {
        const pending = this.pending.get(frame.request_id);
        if (!pending || pending.version !== frame.protocol_version) throw new Error("Uncorrelated or incompatible response edition.");
        if (this.bound && (frame.state_ref !== this.bound.state_ref ||
            frame.actual_source_ref !== this.bound.actual_source_ref ||
            frame.context_ref !== this.bound.context_ref)) throw new Error("Immutable query state changed.");
        this.pending.delete(frame.request_id);
        pending.release();
        if (frame.error) {
            const entries = frame.error.candidates;
            pending.reject(new FortressError(text(frame.error.code, 80), frame.error.message,
                Array.isArray(entries) ? entries.filter(item => typeof item === "string").slice(0, 50) : []));
        } else pending.resolve(frame);
    }

    private failAll(error: Error) {
        for (const request of this.pending.values()) {
            request.release();
            request.reject(error);
        }
        this.pending.clear();
    }

    stop(error = new FortressError("SERVICE_CLOSED", "Fortress inspection closed.")): Promise<void> {
        if (this.phase === "closed") return this.closed;
        if (this.disposal) return this.disposal;
        this.phase = "closing";
        this.failAll(error);
        this.child.stdin.end();
        const force = setTimeout(() => this.child.kill("SIGKILL"), 750);
        this.disposal = this.closed.finally(() => clearTimeout(force));
        return this.disposal;
    }
}

/** Only caller-constructed read-only CLI argument lists may reach this boundary. */
export function projection(launch: Launch, args: string[], signal: AbortSignal, max = 16 * 1024 * 1024, accepted = [0]): Promise<Buffer> {
    if (signal.aborted) return Promise.reject(cancelled());
    return new Promise((resolve, reject) => {
        const child = start(launch, args);
        const chunks: Buffer[] = [];
        let size = 0;
        let stderr = "";
        let failure: Error | undefined;
        let force: ReturnType<typeof setTimeout> | undefined;
        const stop = (error: Error) => {
            if (failure) return;
            failure = error;
            child.kill();
            force = setTimeout(() => child.kill("SIGKILL"), 750);
        };
        const abort = () => stop(cancelled());
        const timer = setTimeout(() => stop(new FortressError("TIMEOUT", "The read-only operation timed out.")), 120_000);
        signal.addEventListener("abort", abort, { once: true });
        child.stdin.on("error", error => stop(error));
        child.stdin.end();
        child.on("error", error => { failure ??= error; });
        child.stderr.on("data", (chunk: Buffer) => {
            if (stderr.length < 2048) stderr += text(chunk.subarray(0, 2048).toString(), 2048 - stderr.length);
        });
        child.stdout.on("data", (chunk: Buffer) => {
            if (failure) return;
            size += chunk.length;
            if (size > max) stop(new FortressError("RESOURCE_LIMIT", "The read-only result exceeds the editor limit."));
            else chunks.push(chunk);
        });
        child.on("close", code => {
            clearTimeout(timer);
            clearTimeout(force);
            signal.removeEventListener("abort", abort);
            if (failure) reject(failure);
            else if (code === null || !accepted.includes(code)) reject(new FortressError("READ_ONLY_OPERATION_FAILED", stderr || "Fortress could not produce a result."));
            else resolve(Buffer.concat(chunks, size));
        });
    });
}
