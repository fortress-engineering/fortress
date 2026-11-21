import { lstat, mkdtemp, realpath, rmdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import { contains, digest, hash, MAX_FILE, Revision } from "./source";
import { FortressError, type Frame, type Launch, object, projection, type RecordValue, Stdio } from "./transport";

const decoder = new TextDecoder("utf-8", { fatal: true });

export async function trustedLaunch(executable: unknown, roots: string[], cwd: string): Promise<Launch> {
    if (typeof executable !== "string" || !isAbsolute(executable) || /^[\\/]{2}/.test(executable) ||
        (process.platform === "win32" && !/\.exe$/i.test(executable))) {
        throw new Error("Set Fortress: Executable to an absolute installed binary in User Settings.");
    }
    const resolved = await realpath(executable);
    const physicalRoots = await Promise.all(roots.map(root => realpath(root)));
    if (relative(executable, resolved) || !(await lstat(resolved)).isFile() ||
        physicalRoots.some(root => contains(root, resolved))) {
        throw new Error("Select an ordinary installed Fortress executable outside the opened workspace folders.");
    }
    return { executable: resolved, cwd };
}

class TransientFiles {
    private dir?: string;
    private serial = 0;
    private readonly files = new Set<string>();

    async save(bytes: Uint8Array) {
        if (this.files.size >= 5) throw new FortressError("RESOURCE_LIMIT", "Too many retained editor inputs.");
        this.dir ??= await mkdtemp(join(tmpdir(), "fortress-editor-"));
        const path = join(this.dir, `input-${++this.serial}.json`);
        await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
        this.files.add(path);
        return path;
    }
    async release(path: string) {
        if (!this.files.has(path)) return;
        await unlink(path);
        this.files.delete(path);
    }
    async close() {
        for (const path of this.files) await this.release(path);
        if (this.dir) await rmdir(this.dir);
    }
}

export type Page = { total: number; offset: number; records: {kind: string; id: string; value: unknown; scope_ref: string}[]; next_cursor: string | null };
export function page(value: unknown): Page {
    const result = object(value);
    const { total, offset, records, next_cursor } = result;
    if (typeof total !== "number" || typeof offset !== "number" || !Number.isSafeInteger(total) ||
        !Number.isSafeInteger(offset) || total < 0 || offset < 0 || offset > total ||
        !Array.isArray(records) || records.length > 200 || records.length + offset > total ||
        (next_cursor !== null && (typeof next_cursor !== "string" || !next_cursor.length || next_cursor.length > 8192)) ||
        (offset + records.length < total) !== (next_cursor !== null) || (next_cursor !== null && records.length === 0)) {
        throw new Error("Fortress returned an invalid bounded page.");
    }
    for (const entry of records) {
        const record = object(entry);
        if (typeof record.id !== "string" || typeof record.kind !== "string" || typeof record.scope_ref !== "string") {
            throw new Error("An indexed record is missing its original identity.");
        }
    }
    return result as Page;
}

export class WorkspaceService {
    readonly revision = new Revision();
    private readonly files = new TransientFiles();
    private server?: Stdio;
    private closing = Promise.resolve();
    private active?: Promise<unknown>;
    private state?: string;
    private proposal?: string;
    private disposed = false;
    readonly remembered = new Set<string>();
    status?: Frame;

    constructor(readonly root: string, readonly launch: Launch) {}

    invalidate() {
        this.revision.change();
        this.status = undefined;
        const server = this.server;
        this.server = undefined;
        if (server) this.closing = Promise.all([this.closing, server.stop()]).then(() => {});
    }

    private operation<T>(work: (signal: AbortSignal) => Promise<T>): Promise<T> {
        if (this.disposed || this.active) return Promise.reject(new FortressError("BUSY", "Wait for the current Fortress operation or cancel it."));
        this.invalidate();
        const token = this.revision.capture();
        const pending = work(token.signal).then(result => {
            if (!token.valid()) throw new FortressError("CANCELLED", "The workspace changed during the operation.");
            return result;
        });
        this.active = pending;
        return pending.finally(() => { this.active = undefined; });
    }

    refresh(extra: string[] = []): Promise<Frame> {
        return this.operation(signal => this.connect(signal, extra));
    }

    private async connect(signal: AbortSignal, extra: string[] = []) {
        await this.closing;
        if (signal.aborted) throw new FortressError("CANCELLED", "The workspace changed before loading.");
        const args = ["serve", "--stdio", this.root];
        if (this.state) args.push("--state", this.state);
        if (this.proposal) args.push("--proposal", this.proposal);
        const server = new Stdio(this.launch, args.concat(extra));
        this.server = server;
        try {
            const status = await server.negotiate(signal);
            if (signal.aborted) throw new FortressError("CANCELLED", "The workspace changed while loading.");
            if (status.result?.kind !== "STATUS") throw new Error("Expected Fortress status.");
            this.status = status;
            return status;
        } catch (error) {
            await server.stop();
            if (this.server === server) this.server = undefined;
            throw error;
        }
    }

    current() {
        if (!this.server || !this.status) throw new FortressError("UNAVAILABLE", "Refresh Fortress inspection first.");
        const server = this.server;
        const token = this.revision.capture();
        return { server, status: this.status, ...token,
            call: async (method: string, parameters: RecordValue = {}) => {
                const reply = await server.call(method, parameters, token.signal);
                if (!token.valid()) throw new FortressError("CANCELLED", "Discarded a response for an older workspace revision.");
                return reply;
            }
        };
    }

    recheck(): Promise<Frame> {
        return this.operation(async signal => {
            await this.closing;
            const result = await projection(this.launch, ["state-view", this.root, "--format", "json"], signal);
            const value = object(JSON.parse(decoder.decode(result)));
            if (!digest(value.source_ref)) throw new Error("Fortress returned an invalid state view binding.");
            if (signal.aborted) throw new FortressError("CANCELLED", "Discarded the changed repository state.");
            const path = await this.files.save(result);
            const previous = this.state;
            this.state = path;
            if (previous) {
                for (const old of this.remembered) await this.files.release(old);
                this.remembered.clear();
                this.remembered.add(previous);
            }
            return this.connect(signal);
        });
    }

    compare(paths?: [string, string]) {
        const [before, after] = paths ?? [[...this.remembered][0], this.state];
        if (!before || !after) throw new Error("Capture two saved states or select two existing comparison records.");
        return this.refresh(["--comparison-state", before, "--comparison-state", after]);
    }

    inspectCandidate(path: string) { return this.refresh(["--proposal", path]); }

    preview(path: string, before: Buffer, after: Buffer, document: AbortSignal): Promise<Frame> {
        if (before.length > MAX_FILE || after.length > MAX_FILE) throw new Error("The buffer exceeds the supported byte limit.");
        if (before.equals(after)) throw new Error("The buffer has no byte changes.");
        return this.operation(async revision => {
            const signal = AbortSignal.any([revision, document]);
            await this.closing;
            const args = ["--root", this.root, "--format", "json"];
            const observed = object(JSON.parse(decoder.decode(await projection(this.launch, ["overlay", "base", ...args], signal))));
            if (observed.status !== "OBSERVED_BASE" || !digest(observed.base_source_ref) ||
                !digest(observed.context_ref) || observed.request_schema_version !== 1) {
                throw new Error("The installed Fortress does not supply an exact supported candidate base.");
            }
            const request = await this.files.save(Buffer.from(JSON.stringify({
                schema_version: 1, base_source_ref: observed.base_source_ref, context_ref: observed.context_ref,
                operations: [{ kind: "REPLACE_FILE", path, preimage: [...before], postimage: [...after] }]
            })));
            try {
                const response = await projection(this.launch, ["overlay", "evaluate", ...args, "--request", request], signal);
                const evaluated = object(JSON.parse(decoder.decode(response)));
                if (evaluated.status !== "PROPOSED" || evaluated.actual_state !== false ||
                    evaluated.base_inventory_ref !== observed.base_source_ref ||
                    evaluated.context_ref !== observed.context_ref || !digest(evaluated.evaluation_ref) ||
                    !digest(evaluated.candidate_digest) || !digest(evaluated.predicted_state_ref)) {
                    throw new Error("Fortress returned a candidate with an incompatible or stale binding.");
                }
                if (signal.aborted) throw new FortressError("CANCELLED", "Discarded a preview for an older buffer.");
                const old = this.proposal;
                this.proposal = await this.files.save(response);
                if (old) await this.files.release(old);
                return this.connect(signal);
            } finally { await this.files.release(request); }
        });
    }

    async dispose() {
        if (this.disposed) return;
        this.disposed = true;
        this.invalidate();
        await this.active?.catch(() => {});
        await this.closing;
        await this.files.close();
    }
}

/** Keep the original UTF-8 BOM and the buffer's selected line ending. */
export function bufferBytes(previous: Buffer, text: string, eol: number): Buffer {
    const decoded = decoder.decode(previous);
    const bom = previous.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]));
    const prefix = bom ? Buffer.from([0xef, 0xbb, 0xbf]) : Buffer.alloc(0);
    if (decoded.includes("\0")) throw new Error("Binary or unsupported saved source.");
    const newline = eol === 2 ? "\r\n" : "\n";
    const updated = text.replace(/\r\n|\n|\r/g, newline);
    if (/[\uD800-\uDFFF]/u.test(updated)) throw new Error("Buffer has an unpaired UTF-16 surrogate.");
    return Buffer.concat([prefix, Buffer.from(updated, "utf8")]);
}

export function sameSource(bytes: Buffer, expected: unknown) {
    return digest(expected) && hash(bytes) === expected;
}
