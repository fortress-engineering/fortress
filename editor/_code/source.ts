import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { isAbsolute, join, relative, sep } from "node:path";

export const MAX_FILE = 1024 * 1024;
export const hash = (bytes: Uint8Array) => "sha256:" + createHash("sha256").update(bytes).digest("hex");
export const digest = (value: unknown): value is string => typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);

export function text(value: unknown, limit = 360): string {
    const raw = typeof value === "string" ? value : "";
    const visible = raw.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, " ")
        .replaceAll("$(", "$ (").replaceAll("](", "] (");
    return visible.length > limit ? visible.slice(0, limit) + " …" : visible;
}

export function contains(root: string, file: string): boolean {
    const path = relative(root, file);
    return !isAbsolute(path) && path !== ".." && !path.startsWith(".." + sep);
}

export function portable(path: string): boolean {
    return path.length > 0 && path.length <= 4096 && path.split("/").every(segment =>
        segment.length > 0 && segment !== "." && segment !== ".." &&
        !/[\\:<>|"?*\p{Cc}\p{Cf}]/u.test(segment) &&
        !/[ .]$/.test(segment) && !/^(con|prn|aux|nul|(?:com|lpt)[1-9¹²³]) *(?:\.|$)/i.test(segment));
}

export async function ordinaryRoot(path: string): Promise<string> {
    const clean = await realpath(path);
    if (relative(path, clean) || !(await lstat(clean)).isDirectory()) {
        throw new Error("Select a physical local workspace folder.");
    }
    return clean;
}

export async function readSource(root: string, path: string): Promise<{ file: string; bytes: Buffer }> {
    if (!portable(path)) throw new Error("Unsafe repository-relative source path.");
    let file = root;
    const parts = path.split("/");
    for (const [index, segment] of parts.entries()) {
        file = join(file, segment);
        const stat = await lstat(file);
        if (stat.isSymbolicLink() || !(index + 1 === parts.length ? stat.isFile() : stat.isDirectory())) {
            throw new Error("Source path contains a link or unexpected filesystem object.");
        }
    }
    const resolved = await realpath(file);
    if (!contains(root, resolved) || relative(file, resolved)) throw new Error("Source path escaped its workspace.");
    const handle = await open(file, constants.O_RDONLY | (process.platform === "win32" ? 0 : constants.O_NOFOLLOW));
    try {
        const before = await handle.stat({ bigint: true });
        if (!before.isFile() || before.size > BigInt(MAX_FILE)) throw new Error("Source is unavailable or exceeds the editor limit.");
        const bytes = Buffer.alloc(Number(before.size) + 1);
        let used = 0;
        while (used < bytes.length) {
            const { bytesRead } = await handle.read(bytes, used, bytes.length - used, used);
            if (bytesRead === 0) break;
            used += bytesRead;
        }
        const after = await handle.stat({ bigint: true });
        const named = await lstat(file, { bigint: true });
        if (BigInt(used) !== before.size || before.mtimeNs !== after.mtimeNs ||
            before.ctimeNs !== after.ctimeNs || after.dev !== named.dev || after.ino !== named.ino ||
            named.mtimeNs !== after.mtimeNs || named.ctimeNs !== after.ctimeNs ||
            named.size !== after.size || relative(await realpath(file), file)) {
            throw new Error("Source changed while it was being read.");
        }
        return { file, bytes: bytes.subarray(0, used) };
    } finally { await handle.close(); }
}

type ColumnUnit = "utf8" | "scalar" | "utf16" | "unspecified";
type Position = [line: number, character: number];

function offset(line: string, column: number, end: boolean, unit: ColumnUnit): number | undefined {
    const target = column - 1;
    if (unit === "unspecified") {
        const choices = (["utf8", "scalar", "utf16"] as const).map(kind => offset(line, column, end, kind));
        return choices.every(choice => choice === choices[0]) ? choices[0] : undefined;
    }
    let count = 0;
    let index = 0;
    for (const char of line) {
        if (count === target) return end ? index + char.length : index;
        count += unit === "utf8" ? Buffer.byteLength(char) : unit === "scalar" ? 1 : char.length;
        index += char.length;
    }
    return undefined;
}

export function locate(source: string, raw: unknown, unit: ColumnUnit = "unspecified"): [Position, Position] | undefined {
    if (typeof raw !== "object" || raw === null) return;
    const span = raw as Record<string, number>;
    const { start_line: sl, end_line: el, start_column: sc, end_column: ec } = span;
    if (![sl, el, sc, ec].every(n => Number.isSafeInteger(n) && n > 0) || el < sl || (el === sl && ec < sc)) return;
    const lines = source.split(/\r\n|\n|\r/);
    if (el > lines.length) return;
    const start = offset(lines[sl - 1], sc, false, unit);
    const end = offset(lines[el - 1], ec, true, unit);
    if (start !== undefined && end !== undefined) return [[sl - 1, start], [el - 1, end]];
}

/** Invalidation is a hint. Only an exact engine response may settle a revision. */
export class Revision {
    private sequence = 0;
    private current = new AbortController();
    change() {
        this.current.abort();
        this.current = new AbortController();
        this.sequence++;
    }
    capture() {
        const sequence = this.sequence;
        const signal = this.current.signal;
        return { signal, valid: () => sequence === this.sequence && !signal.aborted };
    }
}
