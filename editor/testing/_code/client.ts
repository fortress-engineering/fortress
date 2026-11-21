import assert from "node:assert/strict";
import { lstat, mkdtemp, rm, rmdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { locate, portable, readSource, Revision, text } from "../../_code/source";
import { Frames, FortressError, Stdio } from "../../_code/transport";
import { bufferBytes, page, trustedLaunch, WorkspaceService } from "../../_code/workspace";

const sandbox = { executable: process.execPath, cwd: tmpdir() };
function fixtureScript(advertised: number[]) {
    return `
const readline = require("node:readline");
const ref = "sha256:" + "1".repeat(64);
function serialize(x) {
  if (Array.isArray(x)) return "["+x.map(serialize).join(",")+"]";
  if (x && typeof x === "object") return "{"+Object.keys(x).sort().map(k=>JSON.stringify(k)+":"+serialize(x[k])).join(",")+"}";
  return JSON.stringify(x);
}
function respond(request, kind, data, error = null) {
  const v = request.protocol_version;
  process.stdout.write(serialize({
    "$schema": "urn:fortress:protocol:v"+v+":query-response",
    protocol_version:v, request_id:request.request_id, state_ref:ref, context_ref:null,
    actual_source_ref:ref, selected_source_ref:null, source_freshness:"MISSING",
    result:error ? null : {kind,data}, error, limitations:[], operational_state:error ? "FAILED" : "COMPLETED"
  })+"\\n");
}
const waiting = new Map();
readline.createInterface({ input: process.stdin }).on("line", line => {
  const request = JSON.parse(line);
  if (request.method === "protocol") respond(request,"PROTOCOL",{
    protocol_versions:${JSON.stringify(advertised)},
    methods:["status","query","doctor","cancel","explain"],
    max_request_bytes:4096,max_page_size:7,mutation:false
  });
  if (request.method === "status") respond(request, "STATUS",{ evidence:"MISSING", raw:"FAIL", enforcement:"NON_BLOCKING", assurance:"UNKNOWN" });
  if (request.method === "doctor") waiting.set(request.request_id,request);
  if (request.method === "cancel") {
    const selected = waiting.get(request.parameters.request_id);
    respond(request,"PROTOCOL",{active:!!selected});
    if (selected) respond(selected,"",null,{code:"CANCELLED",message:"Interrupted"});
  }
  if (request.method === "explain") {
    if (request.parameters.selector === "crash") process.exit(17);
    else process.stdout.write("x".repeat(1048577));
  }
  if (request.method === "query") {
    if (request.parameters.kind === "wrong-id") respond({...request,request_id:"unknown"},"PAGE",{});
    else respond(request,"PAGE",{total:2,offset:request.parameters.page?.cursor ? 1 : 0,records:[{id:request.parameters.page?.cursor ? "B" : "A",kind:"route",scope_ref:"Consumer",value:{consumer:"Consumer",provider:"Provider"}}],next_cursor:request.parameters.page?.cursor ? null : "exact-next"});
  }
});`;
}

function fixture(advertised: number[]) { return new Stdio(sandbox, ["-e", fixtureScript(advertised)], 1000); }

test("negotiates the highest shared edition and preserves independent states and cursor", async () => {
    const client = fixture([2, 4, 9]);
    try {
        const status = await client.negotiate();
        assert.equal(status.protocol_version, 4);
        assert.deepEqual(status.result?.data, { evidence: "MISSING", raw: "FAIL", enforcement: "NON_BLOCKING", assurance: "UNKNOWN" });
        assert.equal(client.pageSize, 7);
        const first = page((await client.call("query", { kind: "routes" })).result?.data);
        const second = page((await client.call("query", { kind: "routes", page: { cursor: first.next_cursor } })).result?.data);
        assert.deepEqual([first.records[0].id, second.records[0].id], ["A", "B"]);
        assert.equal(second.next_cursor, null);
        await assert.rejects(client.call("author"), { code: "UNAVAILABLE" });
    } finally { await client.stop(); }
});

test("unsupported protocol and request/response limits remain errors", async () => {
    const unsupported = fixture([7]);
    try { await assert.rejects(unsupported.negotiate(), /share no supported/); }
    finally { await unsupported.stop(); }
    const client = fixture([1, 5]);
    try {
        await client.negotiate();
        await assert.rejects(client.call("query", { selector: "a".repeat(5000) }), { code: "RESOURCE_LIMIT" });
        await assert.rejects(client.call("explain", { selector: "oversized" }), { code: "INVALID_RESPONSE" });
    } finally { await client.stop(); }
});

test("partial, malformed UTF-8 and duplicate responses fail before publication", () => {
    let delivered = 0;
    const receive = () => { delivered++; };
    const partial = new Frames();
    partial.push(Buffer.from('{"request_id":"1"'), receive);
    assert.throws(() => partial.finish(), /mid-frame/);
    const invalidUtf8 = new Frames();
    assert.throws(() => invalidUtf8.push(Buffer.from([0xff, 10]), receive));
    const duplicate = new Frames();
    assert.throws(() => duplicate.push(Buffer.from('{"request_id":"1","request_id":"2"}\n'), receive), /noncanonical/);
    assert.equal(delivered, 0);
});

test("cancellation and backpressure retire bounded active work", async () => {
    const client = fixture([5]);
    try {
        await client.negotiate();
        const handles = Array.from({ length: 8 }, () => new AbortController());
        const pending = handles.map(controller => client.call("doctor", {}, controller.signal).catch(error => error));
        await assert.rejects(client.call("doctor"), { code: "RESOURCE_LIMIT" });
        for (const handle of handles) handle.abort();
        const results = await Promise.all(pending);
        assert.ok(results.every(error => error instanceof FortressError && error.code === "CANCELLED"));
    } finally { await client.stop(); }
});

test("crash, uncorrelated frame, and startup failure cannot become a result", async () => {
    for (const [method, parameters, code] of [
        ["explain", { selector: "crash" }, "SERVICE_CLOSED"],
        ["query", { kind: "wrong-id" }, "INVALID_RESPONSE"]
    ] as const) {
        const client = fixture([5]);
        try {
            await client.negotiate();
            await assert.rejects(client.call(method, parameters), { code });
        } finally { await client.stop(); }
    }
    const unavailable = new Stdio({ ...sandbox, executable: join(tmpdir(), "fortress-nonexistent-binary") }, []);
    try { await assert.rejects(unavailable.negotiate(), { code: "START_FAILED" }); }
    finally { await unavailable.stop(); }
});

test("saved and unsaved revisions and Unicode locations remain independent", () => {
    const first = new Revision(), second = new Revision();
    const old = first.capture(), current = second.capture();
    first.change();
    assert.equal(old.valid(), false);
    assert.equal(current.valid(), true);
    const span = { start_line: 2, end_line: 2, start_column: 5, end_column: 5 };
    assert.deepEqual(locate("one\r\n😀X", span, "utf8"), [[1, 2], [1, 3]]);
    assert.equal(locate("one\r\n😀X", span), undefined);
    assert.deepEqual(locate("one\r\nX😀", { ...span, start_column: 1, end_column: 2 }), [[1, 0], [1, 3]]);
    assert.deepEqual(bufferBytes(Buffer.from([0xef, 0xbb, 0xbf, 97]), "a\nb", 2), Buffer.from("\uFEFFa\r\nb"));
    assert.throws(() => bufferBytes(Buffer.from([0xff]), "a", 1));
});

test("overlapping refreshes retain the admitted result and invalidate old handles on restart", async () => {
    const root = await mkdtemp(join(tmpdir(), "fortress-editor-service-"));
    const entry = join(root, "serve");
    const service = new WorkspaceService(root, { executable: process.execPath, cwd: root });
    try {
        await writeFile(entry, fixtureScript([5]));
        const accepted = service.refresh();
        await assert.rejects(service.refresh(), { code: "BUSY" });
        assert.equal((await accepted).result?.kind, "STATUS");
        const old = service.current();
        assert.equal((await service.refresh()).result?.kind, "STATUS");
        assert.equal(old.valid(), false);
        await assert.rejects(old.call("status"), error => error instanceof FortressError && ["CANCELLED", "SERVICE_CLOSED"].includes(error.code));
    } finally { await service.dispose(); await rm(entry, { force: true }); await rmdir(root); }
});

test("hostile display, paths, missing sources and workspace installers are explicit", async () => {
    assert.equal(text("a\u001b[31m\u202E\n"), "a [31m  ");
    for (const path of ["../escape", "a/../b", "C:/file.rs", "x\\y", "a/CON.rs", "a/COM¹.rs", "a/CON .rs", "/absolute", "a//b", "command:evil"]) assert.equal(portable(path), false);
    const root = await mkdtemp(join(tmpdir(), "fortress-editor-source-"));
    const path = join(root, process.platform === "win32" ? "fortress.exe" : "fortress");
    try {
        await writeFile(path, "fixture");
        await assert.rejects(trustedLaunch(path, [root], root), /outside/);
        const file = await readSource(root, path.slice(root.length + 1));
        assert.equal(file.bytes.toString(), "fixture");
        await rm(path);
        await assert.rejects(readSource(root, path.slice(root.length + 1)));
        assert.ok((await lstat(root)).isDirectory());
    } finally { await rm(path, { force: true }); await rmdir(root); }
    assert.throws(() => page({ total: 2, offset: 0, records: [], next_cursor: "none" }));
});
