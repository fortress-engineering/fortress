import * as vscode from "vscode";
import { relative, sep } from "node:path";
import { lstat } from "node:fs/promises";
import { contains, digest, locate, ordinaryRoot, readSource, text } from "./source";
import { FortressError, type Frame, object, type RecordValue } from "./transport";
import { bufferBytes, page, type Page, sameSource, trustedLaunch, WorkspaceService } from "./workspace";

const findingSource = "Fortress";
const sourceDecoder = new TextDecoder("utf-8", { fatal: true });
const diagnosticLimit = 500;
const knownCommands = [
    "menu", "refresh", "recheck", "status", "doctor", "findings", "architecture", "explain",
    "author", "previewBuffer", "inspectProposal", "compare", "close"
] as const;
type Command = typeof knownCommands[number];
type Pick = vscode.QuickPickItem & { select: () => Promise<unknown> };
type Root = { folder: vscode.WorkspaceFolder; service: WorkspaceService; diagnostics: vscode.DiagnosticCollection; watchers: vscode.Disposable[]; suppressed: string; changes: number };
type Finding = { raw: RecordValue; enforcement?: RecordValue; bytes: unknown };
type Anchor = { root: string; reference: string; state: string };

function record(value: unknown): RecordValue | undefined {
    return value && typeof value === "object" && !Array.isArray(value) ? value as RecordValue : undefined;
}
function readable(value: unknown, indent = ""): string {
    if (value === null || value === undefined) return "Unavailable";
    if (Array.isArray(value)) return value.length ? "\n" + value.map(entry => indent + "• " + readable(entry, indent + "  ")).join("\n") : "None recorded";
    const fields = record(value);
    if (fields) return "\n" + Object.entries(fields).map(([key, entry]) =>
        indent + text(key.replace(/_/g, " ")) + "  " + readable(entry, indent + "  ")).join("\n");
    return typeof value === "string" ? text(value, 1_048_576) : String(value);
}

function finding(row: Page["records"][number]): Finding {
    const value = object(row.value);
    const raw = object(value.finding);
    if (row.kind !== "finding" || raw.finding_id !== row.id) throw new Error("Finding identity does not match the indexed record.");
    const enforcement = record(value.recorded_enforcement);
    if (enforcement && enforcement.finding_id !== row.id) throw new Error("Enforcement identity does not match the finding.");
    return { raw, enforcement, bytes: value.observed_file_digest };
}

class Views implements vscode.TextDocumentContentProvider {
    private readonly content = new Map<string, string>();
    private index = 0;
    provideTextDocumentContent(uri: vscode.Uri) { return this.content.get(uri.path) ?? "This immutable Fortress view was released."; }

    async show(title: string, content: string) {
        if (Buffer.byteLength(content) > 2 * 1024 * 1024) {
            throw new FortressError("RESOURCE_LIMIT", "This view exceeds the text limit. Narrow the selection.");
        }
        const path = "/" + (++this.index) + "/" + title.replace(/[^a-zA-Z0-9 -]/g, "") + ".txt";
        this.content.set(path, content);
        if (this.content.size > 8) this.content.delete(this.content.keys().next().value!);
        const document = await vscode.workspace.openTextDocument(vscode.Uri.from({ scheme: "fortress-view", path }));
        await vscode.window.showTextDocument(document, { preview: true, preserveFocus: false });
    }
    release(document: vscode.TextDocument) { this.content.delete(document.uri.path); }
}

class Editor {
    private readonly roots = new Map<string, Root>();
    private readonly views = new Views();
    private readonly bar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 20);
    private readonly log = vscode.window.createOutputChannel("Fortress", { log: true });
    private readonly anchors = new WeakMap<vscode.Diagnostic, Anchor>();
    private readonly refreshHints = new Map<string, ReturnType<typeof setTimeout>>();
    private readonly closing = new Set<Promise<void>>();
    private selected?: string;

    constructor(context: vscode.ExtensionContext) {
        context.subscriptions.push(this.bar, this.log, vscode.workspace.registerTextDocumentContentProvider("fortress-view", this.views));
        this.bar.command = "fortress.menu";
        this.bar.text = "$(shield) Fortress";
        this.bar.accessibilityInformation = { label: "Fortress repository commands" };
        this.bar.show();
        for (const name of knownCommands) {
            context.subscriptions.push(vscode.commands.registerCommand("fortress." + name, (argument?: unknown) =>
                this.dispatch(name, argument).catch(error => {
                    const code = error instanceof FortressError ? error.code : "UNAVAILABLE";
                    const message = text((error as Error).message, 1100);
                    this.log.warn(`${name} · ${text(code, 48)} · ${message}`);
                    this.bar.text = "$(shield) Fortress: " + text(code, 48);
                    this.bar.tooltip = message;
                    if (code !== "CANCELLED") void vscode.window.showWarningMessage("Fortress · " + code + " · " + message);
                    return undefined;
                })));
        }
        context.subscriptions.push(
            vscode.workspace.onDidChangeWorkspaceFolders(event => {
                for (const folder of event.removed) this.closeRoot(folder.uri.toString());
            }),
            vscode.workspace.onDidChangeConfiguration(event => {
                if (event.affectsConfiguration("fortress.executable")) for (const key of this.roots.keys()) this.closeRoot(key);
            }),
            vscode.workspace.onDidCloseTextDocument(document => {
                if (document.uri.scheme === "fortress-view") this.views.release(document);
            }),
            vscode.workspace.onDidChangeTextDocument(event => {
                if (!event.contentChanges.length) return;
                for (const value of this.roots.values()) value.diagnostics.delete(event.document.uri);
            }),
            vscode.workspace.onDidSaveTextDocument(document => {
                const folder = vscode.workspace.getWorkspaceFolder(document.uri);
                if (folder) this.changed(folder.uri.toString());
            }),
            vscode.languages.registerCodeActionsProvider({ scheme: "file" }, {
                provideCodeActions: (_document, _range, action) => action.diagnostics.flatMap(diagnostic => {
                    const anchor = this.anchors.get(diagnostic);
                    if (!anchor) return [];
                    const result = new vscode.CodeAction("Fortress: Explain finding", vscode.CodeActionKind.QuickFix);
                    result.diagnostics = [diagnostic];
                    result.command = { command: "fortress.explain", title: result.title, arguments: [anchor] };
                    return [result];
                })
            })
        );
    }

    private changed(key: string) {
        const root = this.roots.get(key);
        if (!root) return;
        root.changes++;
        root.diagnostics.clear();
        root.service.invalidate();
        clearTimeout(this.refreshHints.get(key));
        this.refreshHints.set(key, setTimeout(() => {
            this.refreshHints.delete(key);
            if (this.selected === key && !root.service.status) {
                this.bar.text = "$(shield) Fortress: Refresh needed";
                this.bar.tooltip = "Workspace changes invalidate the loaded observation. Refresh to check exact saved source.";
            }
        }, 300));
    }

    private closeRoot(key: string) {
        clearTimeout(this.refreshHints.get(key));
        this.refreshHints.delete(key);
        const root = this.roots.get(key);
        if (!root) return;
        this.roots.delete(key);
        root.diagnostics.dispose();
        root.watchers.forEach(watcher => watcher.dispose());
        const closed = root.service.dispose();
        this.closing.add(closed);
        void closed.catch(error => {
            void vscode.window.showWarningMessage("Fortress retained temporary files · " + text((error as Error).message));
        }).finally(() => this.closing.delete(closed));
        if (key === this.selected) {
            this.selected = undefined;
            this.bar.text = "$(shield) Fortress";
        }
    }

    async dispose() {
        for (const key of this.roots.keys()) this.closeRoot(key);
        await Promise.allSettled(this.closing);
    }

    private async root(explicit?: string, choose = false): Promise<Root | undefined> {
        if (!vscode.workspace.isTrusted || vscode.env.remoteName) {
            throw new Error("Fortress requires a trusted local VS Code workspace.");
        }
        const folders = (vscode.workspace.workspaceFolders ?? []).filter(folder => folder.uri.scheme === "file" && !folder.uri.authority);
        if (!folders.length) throw new Error("Open a local repository folder.");
        const active = vscode.window.activeTextEditor?.document.uri;
        let folder = folders.find(candidate => candidate.uri.toString() === explicit);
        if (explicit && !folder) throw new Error("The selected repository is closed.");
        if (!folder && !choose) folder = active && vscode.workspace.getWorkspaceFolder(active);
        folder ??= !choose ? folders.find(candidate => candidate.uri.toString() === this.selected) : undefined;
        folder ??= folders.length === 1 ? folders[0] : (await vscode.window.showQuickPick(
            folders.map(item => ({ label: text(item.name), detail: text(item.uri.fsPath), folder: item })), { placeHolder: "Select a Fortress repository" }
        ))?.folder;
        if (!folder) return;
        const key = folder.uri.toString();
        this.selected = key;
        const existing = this.roots.get(key);
        if (existing) return existing;
        if (this.roots.size + this.closing.size >= 4) throw new Error("Close one Fortress repository before opening another.");
        const physical = await ordinaryRoot(folder.uri.fsPath);
        const executable = vscode.workspace.getConfiguration("fortress").inspect("executable")?.globalValue;
        const launch = await trustedLaunch(executable, folders.map(item => item.uri.fsPath), __dirname);
        if (!vscode.workspace.isTrusted || !vscode.workspace.workspaceFolders?.some(item => item.uri.toString() === key)) return;
        const other = this.roots.get(key);
        if (other) return other;
        if (this.roots.size + this.closing.size >= 4) throw new Error("Close one Fortress repository before opening another.");
        const watchers = ["**/*", ".git/HEAD", ".git/refs/**"].map(pattern => {
            const watcher = vscode.workspace.createFileSystemWatcher(new vscode.RelativePattern(folder!, pattern));
            watcher.onDidChange(() => this.changed(key));
            watcher.onDidCreate(() => this.changed(key));
            watcher.onDidDelete(() => this.changed(key));
            return watcher;
        });
        const result: Root = { folder, service: new WorkspaceService(physical, launch), watchers,
            diagnostics: vscode.languages.createDiagnosticCollection("fortress"), suppressed: "", changes: 0 };
        this.roots.set(key, result);
        return result;
    }

    private async menu() {
        const commands = [
            ["Refresh saved-source status", "refresh"], ["Recheck saved source", "recheck"],
            ["Repository status", "status"], ["Doctor", "doctor"], ["Findings", "findings"],
            ["Architecture and policy", "architecture"], ["Explain an identity", "explain"],
            ["Preview policy or schema guidance", "author"], ["Preview unsaved buffer", "previewBuffer"],
            ["Inspect retained proposal", "inspectProposal"], ["Compare saved states", "compare"],
            ["Close inspection", "close"]
        ];
        const selected = await vscode.window.showQuickPick(commands.map(([label, command]) => ({ label, command })), { placeHolder: "Fortress developer commands" });
        if (selected) return vscode.commands.executeCommand("fortress." + selected.command);
    }

    private async dispatch(command: Command, argument: unknown) {
        if (command === "menu") return this.menu();
        const options = record(argument);
        const anchor = command === "explain" ? options : undefined;
        const explicit = typeof options?.root === "string" ? options.root : undefined;
        const root = await this.root(explicit, command === "refresh");
        if (!root) return;
        if (command === "close") return this.closeRoot(root.folder.uri.toString());
        if (command === "refresh" || command === "recheck") {
            const status = await this.busy(root, command === "recheck" ? "Rechecking saved source" : "Loading repository evidence",
                token => this.observeSaved(root, command, token));
            if (root.service.status !== status) throw new FortressError("CANCELLED", "Discarded status for an older workspace observation.");
            await this.showStatus(root, status);
            return status;
        }
        if (command === "previewBuffer") return this.preview(root);
        if (command === "inspectProposal") {
            const path = await this.selectArtifact("Open a retained Fortress proposal");
            if (!path) return;
            await this.busy(root, "Loading retained proposal", () => root.service.inspectCandidate(path));
            return this.browse(root, "candidate", {});
        }
        if (command === "compare") return this.compare(root);

        if (!root.service.status) await this.busy(root, "Loading repository evidence", () => root.service.refresh());
        const current = root.service.current();
        if (command === "status") {
            await this.showStatus(root, current.status);
            return current.status;
        }
        if (command === "doctor") {
            const reply = await current.call("doctor");
            await this.views.show("Fortress doctor", "Read-only repository diagnosis\n" + readable(reply.result?.data));
            return reply;
        }
        if (command === "findings") {
            if (current.server.metadata.finding_inventory !== true) throw new Error("The installed Fortress does not advertise finding inventory. Exact explanation IDs remain available.");
            return this.browse(root, "query", { kind: "findings" });
        }
        if (command === "architecture") return this.browse(root, "query", { kind: "modules" });
        if (command === "author") return this.author(root, record(argument));
        if (anchor && anchor.state !== current.status.state_ref) throw new Error("The diagnostic belongs to an older observation. Refresh diagnostics.");
        const selector = typeof anchor?.reference === "string" ? anchor.reference :
            await vscode.window.showInputBox({ prompt: "Finding, claim, obligation, evidence, or Module identity" });
        if (selector && selector.length <= 4096) return this.browse(root, "explain", { selector });
    }

    private async observeSaved(root: Root, command: "refresh" | "recheck", token: vscode.CancellationToken) {
        for (let attempt = 0; ; attempt++) {
            const before = root.changes;
            if (token.isCancellationRequested || this.roots.get(root.folder.uri.toString()) !== root) {
                throw new FortressError("CANCELLED", "Saved-source inspection was cancelled.");
            }
            try {
                const status = await (command === "recheck" ? root.service.recheck() : root.service.refresh());
                if (root.service.status !== status) throw new FortressError("CANCELLED", "The workspace changed before placing diagnostics.");
                await this.diagnostics(root);
                if (root.service.status !== status) throw new FortressError("CANCELLED", "The workspace changed while placing diagnostics.");
                return status;
            } catch (error) {
                if (attempt !== 0 || root.changes === before || !(error instanceof FortressError) || error.code !== "CANCELLED") throw error;
                await new Promise(resolve => setTimeout(resolve, 300));
            }
        }
    }

    private async busy<T>(root: Root, title: string, run: (token: vscode.CancellationToken) => Promise<T>): Promise<T> {
        return vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: "Fortress · " + title, cancellable: true },
            async (_progress, token) => {
                const selected = () => this.selected === root.folder.uri.toString();
                if (selected()) this.bar.text = "$(sync~spin) Fortress: " + title;
                root.diagnostics.clear();
                const cancel = token.onCancellationRequested(() => root.service.invalidate());
                try {
                    const result = await run(token);
                    if (selected()) this.bar.text = "$(shield) Fortress: " + (root.service.status?.source_freshness ?? "Unavailable");
                    return result;
                } finally { cancel.dispose(); }
            });
    }

    private async showStatus(root: Root, response: Frame) {
        const status = object(response.result?.data);
        const details = {
            "saved source": response.actual_source_ref,
            "selected evidence source": response.selected_source_ref,
            "selected context": response.context_ref,
            authority: status.actual_authority, standard: status.standard, profiles: status.profiles,
            "actual profiles": status.actual_profiles, "authority freshness": status.authority_freshness,
            "context freshness": status.actual_context_freshness, evidence: status.evidence_state,
            "generation": status.generation_digest, authenticity: status.authenticity,
            "raw conformance": status.raw_conformance, "progressive enforcement": status.progressive_enforcement,
            assurance: record(status.assurance_assessment)?.decision, coverage: status.coverage,
            "unsupported or unknown": status.unsupported_unknown, "finding count": status.finding_count,
            "local materialization": status.local_materialization, limitations: [status.freshness_limit, ...response.limitations]
        };
        await this.views.show("Fortress status", `${text(root.folder.name)} · Evidence ${response.source_freshness} at observation\n${root.suppressed}\n` + readable(details));
    }

    private async browse(root: Root, method: string, parameters: RecordValue): Promise<Frame | undefined> {
        const current = root.service.current();
        let cursor: string | null = null;
        let offset = 0;
        let total: number | undefined;
        while (current.valid()) {
            const reply: Frame = await current.call(method, { ...parameters, page: { limit: current.server.pageSize, cursor } });
            const data = object(reply.result?.data);
            const records = page(data.evidence ?? data.deltas ?? data);
            if (records.offset !== offset || (total !== undefined && records.total !== total)) throw new Error("Fortress paging changed its exact inventory.");
            const description = data.description;
            if (description) {
                const title = method === "candidate" ? "Fortress hypothetical proposal" : "Fortress explanation";
                const heading = method === "candidate" ? "PROPOSED · Unapplied · Authorization has not been verified\n" : "";
                await this.views.show(title, heading + `Evidence ${reply.source_freshness} at observation · ${text(reply.state_ref)}\n` + readable(description));
            }
            const options: Pick[] = records.records.map(row => ({
                label: this.rowLabel(row), description: text(row.kind, 75), detail: text(row.id, 200),
                select: () => this.row(root, row, current)
            }));
            if (records.next_cursor) options.push({ label: "Next page", detail: `${records.offset + records.records.length} of ${records.total} shown`, select: async () => {} });
            if (!options.length) {
                if (!description) await this.views.show("Fortress results", "No records were supplied for this exact selection.");
                return reply;
            }
            const selected = await vscode.window.showQuickPick(options, { placeHolder: `Fortress · ${records.total} recorded rows`, matchOnDetail: true });
            if (!current.valid() || !selected) return reply;
            if (selected !== options[records.records.length]) {
                await selected.select();
                return reply;
            }
            total = records.total;
            offset += records.records.length;
            cursor = records.next_cursor;
        }
    }

    private rowLabel(row: Page["records"][number]) {
        const value = record(row.value);
        if (row.kind === "finding" && record(value?.finding)) {
            const item = finding(row);
            return text(item.raw.rule_id) + " · " + text(item.enforcement?.enforcement ?? "Enforcement unavailable") + " · " + text(item.raw.message);
        }
        return text(value?.qualified_name ?? value?.label ?? value?.path ?? value?.pointer ?? row.id, 240);
    }

    private async row(root: Root, row: Page["records"][number], current: ReturnType<WorkspaceService["current"]>) {
        if (row.kind === "PROPOSED_CANDIDATE") return this.browse(root, "candidate", { candidate_ref: row.id });
        if (row.kind === "module") {
            const choices = ["policy", "dependents", "routes", "relationships", "references", "explain"];
            const selected = await vscode.window.showQuickPick(choices, { placeHolder: this.rowLabel(row) });
            if (!current.valid() || !selected) return;
            return selected === "explain" ? this.browse(root, "explain", { selector: row.id }) :
                this.browse(root, "query", { kind: selected, selector: row.id });
        }
        if (row.kind === "finding" && record(record(row.value)?.finding)) {
            const item = finding(row);
            const actions = await vscode.window.showQuickPick(["Explain finding", "Go to source", "Inspect governing Module", "Recorded finding and enforcement"], { placeHolder: this.rowLabel(row) });
            if (!current.valid() || !actions) return;
            if (actions === "Explain finding") return this.browse(root, "explain", { selector: row.id });
            if (actions === "Inspect governing Module") {
                const entities = Array.isArray(item.raw.entities) ? item.raw.entities.filter(value => typeof value === "string") : [];
                if (!entities.length) throw new Error("The finding has no declared Module reference.");
                const selected = await vscode.window.showQuickPick(entities.map(id => ({ label: text(id), id })), { placeHolder: "Select an exact recorded entity" });
                if (selected && current.valid()) return this.browse(root, "query", { kind: "modules", selector: selected.id });
                return;
            }
            if (actions === "Go to source") {
                const position = await this.location(root, item);
                if (!current.valid() || !position) throw new Error("This finding has no verified current source position. See its recorded location and limitations.");
                return vscode.window.showTextDocument(position.document, { selection: position.range });
            }
        }
        return this.views.show("Fortress record", `${text(row.kind)} · ${text(row.id)}\n` + readable(row.value));
    }

    private async location(root: Root, item: Finding) {
        const location = record(item.raw.location);
        if (!digest(item.bytes) || typeof location?.path !== "string") return;
        try {
            const source = await readSource(root.service.root, location.path);
            if (!sameSource(source.bytes, item.bytes)) return;
            const uri = vscode.Uri.file(source.file);
            if (vscode.workspace.getWorkspaceFolder(uri)?.uri.toString() !== root.folder.uri.toString()) return;
            const document = await vscode.workspace.openTextDocument(uri);
            if (document.isDirty) return;
            const saved = sourceDecoder.decode(source.bytes);
            if (saved.replace(/\r\n|\r/g, "\n") !== document.getText().replace(/\r\n|\r/g, "\n")) return;
            const unit = location.column_unit;
            const positions = locate(saved, location.span, unit === "utf8" || unit === "scalar" || unit === "utf16" ? unit : undefined);
            if (!positions) return;
            const range = new vscode.Range(new vscode.Position(...positions[0]), new vscode.Position(...positions[1]));
            return { document, range, version: document.version };
        } catch { return; }
    }

    private async diagnostics(root: Root) {
        const current = root.service.current();
        root.diagnostics.clear();
        root.suppressed = "";
        if (current.status.source_freshness !== "FRESH" || current.server.metadata.finding_inventory !== true) {
            root.suppressed = "Source diagnostics require fresh retained locations and the advertised finding inventory.";
            return;
        }
        let cursor: string | null = null;
        let processed = 0;
        let placed = 0;
        let total = 0;
        const files = new Map<string, { document: vscode.TextDocument; version: number; rows: vscode.Diagnostic[] }>();
        do {
            const reply: Frame = await current.call("query", { kind: "findings", page: { limit: Math.min(diagnosticLimit - processed, current.server.pageSize), cursor } });
            const result = page(reply.result?.data);
            if (processed !== result.offset || (processed > 0 && total !== result.total)) throw new Error("Diagnostic pagination no longer matches its observation.");
            total = result.total;
            processed += result.records.length;
            cursor = result.next_cursor;
            for (const row of result.records) {
                const item = finding(row);
                const location = await this.location(root, item);
                if (!current.valid()) return;
                if (!location) continue;
                const enforcement = item.enforcement?.enforcement;
                const severity = enforcement === "BLOCKING" ? vscode.DiagnosticSeverity.Error :
                    enforcement === "NON_BLOCKING" ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Information;
                const label = text(item.enforcement?.raw_conformance ?? item.raw.state ?? "Recorded finding") +
                    " · " + text(enforcement ?? "Enforcement unavailable") + " · " + text(item.enforcement?.lifecycle ?? "Lifecycle unavailable") +
                    " · " + text(item.enforcement?.evidence_eligibility ?? item.raw.enforcement_eligibility ?? "Eligibility unavailable");
                const diagnostic = new vscode.Diagnostic(location.range, label + " · " + text(item.raw.message, 1000), severity);
                diagnostic.source = findingSource;
                diagnostic.code = text(item.raw.rule_id, 140);
                this.anchors.set(diagnostic, { root: root.folder.uri.toString(), reference: row.id, state: current.status.state_ref });
                const key = location.document.uri.toString();
                const existing = files.get(key) ?? { document: location.document, version: location.version, rows: [] };
                if (existing.version === location.version) existing.rows.push(diagnostic);
                files.set(key, existing);
            }
        } while (cursor !== null && processed < diagnosticLimit);
        if (!current.valid()) return;
        for (const { document, version, rows } of files.values()) {
            if (document.isDirty || document.isClosed || document.version !== version) continue;
            root.diagnostics.set(document.uri, rows);
            placed += rows.length;
        }
        root.suppressed = `${placed} of ${total} retained findings have verified editor diagnostics. Browse Findings for every recorded row.`;
    }

    private async author(root: Root, explicit?: RecordValue) {
        const current = root.service.current();
        const module = typeof explicit?.module === "string" ? explicit.module :
            await vscode.window.showInputBox({ prompt: "Canonical or qualified Module name for schema guidance" });
        if (!module || module.length > 4096 || !current.valid()) return;
        const guidance = await current.call("author", { module });
        await this.views.show("Fortress schema guidance", "Authored policy guidance · Proposed only\n" + readable(guidance.result?.data));
        const guidanceData = object(guidance.result?.data);
        const supported = [guidanceData.supported_effects, guidanceData.supported_capabilities]
            .flatMap(group => Array.isArray(group) ? group : [])
            .filter((value): value is string => typeof value === "string");
        const target = typeof explicit?.target === "string" ? explicit.target :
            (await vscode.window.showQuickPick(supported.map(value => ({ label: text(value), value })), {
                placeHolder: "Select a schema-supported effect or capability, or Escape to keep guidance"
            }))?.value;
        if (!target || !current.valid()) return guidance;
        const disposition = explicit?.disposition === "ALLOW" || explicit?.disposition === "DENY" ? explicit.disposition :
            await vscode.window.showQuickPick(["ALLOW", "DENY"], { placeHolder: "Choose the proposed disposition" });
        if (!disposition || !current.valid()) return guidance;
        const reply = await current.call("author", { module, target, disposition });
        await this.views.show("Fortress policy proposal", "PROPOSED · Review required\n" + readable(reply.result?.data));
        return reply;
    }

    private async preview(root: Root) {
        const document = vscode.window.activeTextEditor?.document;
        if (!document?.isDirty || document.uri.scheme !== "file" ||
            !contains(root.service.root, document.uri.fsPath)) throw new Error("Select a changed UTF-8 file buffer in the chosen repository.");
        const version = document.version;
        const change = new AbortController();
        const watches = [
            vscode.workspace.onDidChangeTextDocument(event => {
                if (event.document === document && event.contentChanges.length) { change.abort(); root.service.invalidate(); }
            }),
            vscode.workspace.onDidCloseTextDocument(closed => {
                if (closed === document) { change.abort(); root.service.invalidate(); }
            })
        ];
        try {
            const path = relative(root.service.root, document.uri.fsPath).split(sep).join("/");
            const original = await readSource(root.service.root, path);
            if (document.isClosed || document.version !== version) throw new Error("The buffer changed before preview preparation.");
            const postImage = bufferBytes(original.bytes, document.getText(), document.eol);
            await this.busy(root, "Evaluating unapplied buffer", () => root.service.preview(path, original.bytes, postImage, change.signal));
            if (document.version !== version || document.isClosed || change.signal.aborted) throw new Error("The buffer changed during preview.");
            return this.browse(root, "candidate", {});
        } finally { watches.forEach(watch => watch.dispose()); }
    }

    private async selectArtifact(title: string) {
        const selected = (await vscode.window.showOpenDialog({ title, canSelectMany: false, filters: { JSON: ["json"] } }))?.[0];
        if (!selected) return;
        if (selected.scheme !== "file" || selected.authority) throw new Error("Select a local file.");
        const info = await lstat(selected.fsPath);
        if (!info.isFile() || info.size > 32 * 1024 * 1024) throw new Error("Select a bounded ordinary Fortress record.");
        return selected.fsPath;
    }

    private async compare(root: Root) {
        const mode = await vscode.window.showQuickPick(["Two captured saved states", "Two retained comparison records"], { placeHolder: "Choose explicit comparison endpoints" });
        if (!mode) return;
        let paths: [string, string] | undefined;
        if (mode === "Two retained comparison records") {
            const before = await this.selectArtifact("Select the earlier comparison record");
            const after = before && await this.selectArtifact("Select the later comparison record");
            if (!before || !after) return;
            paths = [before, after];
        }
        await this.busy(root, "Loading comparison endpoints", () => root.service.compare(paths));
        const { server } = root.service.current();
        const endpoints = server.metadata.comparison_states;
        if (!Array.isArray(endpoints) || endpoints.length !== 2) throw new Error("The loaded endpoints are unavailable or identical.");
        const options = endpoints.map(item => object(item));
        const earlier = await vscode.window.showQuickPick(options.map(item => ({ label: text(item.state_ref), description: text(item.source_ref), item })), { placeHolder: "Select the earlier endpoint" });
        if (!earlier) return;
        const later = options.find(item => item !== earlier.item);
        return this.browse(root, "transition", { from_state_ref: earlier.item.state_ref, to_state_ref: later?.state_ref });
    }
}

let active: Editor | undefined;
export function activate(context: vscode.ExtensionContext) { active = new Editor(context); }
export async function deactivate() { await active?.dispose(); active = undefined; }
