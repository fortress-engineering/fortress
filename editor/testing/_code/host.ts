import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import * as vscode from "vscode";
import { type Frame, object, projection } from "../../_code/transport";
import { page } from "../../_code/workspace";

const extensionId = "fortress-development.fortress-inspection";
const report = process.env.FORTRESS_EDITOR_TEST_REPORT!;
const executable = process.env.FORTRESS_EDITOR_TEST_EXECUTABLE!;
const fixtureModule = "AF-EDITOR-FIXTURE-SCOPE-0001";

async function execute(name: string, args?: unknown): Promise<Frame> {
    const result = await vscode.commands.executeCommand<Frame>("fortress." + name, args);
    assert.ok(result, "No response from Fortress " + name);
    return result;
}

async function waitForView(pathPart: string) {
    for (let attempt = 0; attempt < 900; ++attempt) {
        const active = vscode.window.activeTextEditor?.document.uri;
        if (active?.scheme === "fortress-view" && active.path.includes(pathPart)) return vscode.window.activeTextEditor!.document.getText();
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error("Expected native Fortress view " + pathPart);
}

async function inspectText(name: string, pending: Promise<Frame>) {
    const view = await Promise.race([waitForView(name), pending.then(() => {
        throw new Error("Fortress completed before presenting its " + name + " view");
    })]);
    for (let attempt = 0; attempt < 200; ++attempt) {
        await vscode.commands.executeCommand("workbench.action.closeQuickOpen");
        const response = await Promise.race([pending, new Promise<undefined>(resolve => setTimeout(resolve, 50))]);
        if (response) return { view, response };
    }
    throw new Error("The " + name + " keyboard dismissal did not close the native picker");
}

export async function run() {
    const installed = vscode.extensions.getExtension(extensionId);
    assert.ok(installed);
    if (process.env.FORTRESS_EDITOR_TEST_RESTRICTED === "1") {
        assert.equal(vscode.workspace.isTrusted, false);
        assert.equal(installed.isActive, false);
        assert.equal((await vscode.commands.getCommands(true)).includes("fortress.recheck"), false);
        await writeFile(report, JSON.stringify({ status: "PASS", trust: "RESTRICTED", activated: false }));
        return;
    }

    assert.equal(vscode.workspace.isTrusted, true);
    await vscode.workspace.getConfiguration("fortress").update("executable", executable, vscode.ConfigurationTarget.Global);
    await installed.activate();
    const [folder, second] = vscode.workspace.workspaceFolders ?? [];
    assert.ok(folder && folder.uri.scheme === "file");
    assert.ok(second && second.uri.scheme === "file");
    const selected = { root: folder.uri.toString() };
    const root = folder.uri.fsPath;
    const file = join(root, "src", "lib.rs");
    const before = await readFile(file);

    const started = performance.now();
    const missing = await execute("refresh", selected);
    const startup = performance.now() - started;
    assert.equal(missing.source_freshness, "MISSING");
    const diagnosed = object((await execute("doctor", selected)).result?.data);
    assert.equal(object(diagnosed.environment).project_commands_executed, false);
    const observed = await execute("recheck", selected);
    assert.equal(observed.source_freshness, "FRESH");
    await waitForView("Fortress status");
    const text = vscode.window.activeTextEditor?.document.getText() ?? "";
    assert.match(text, /raw conformance/);
    assert.match(text, /progressive enforcement/);
    assert.match(text, /assurance/);

    const findings = vscode.languages.getDiagnostics(vscode.Uri.file(file)).filter(item => item.source === "Fortress");
    assert.ok(findings.length > 0, "Expected a native diagnostic from the actual saved program");
    assert.match(findings[0].message, /FAIL/);
    assert.equal(findings[0].range.start.line, 1);
    const expected = object(JSON.parse((await projection({ executable, cwd: root },
        ["findings", root, "--format=json"], new AbortController().signal, 4 * 1024 * 1024, [0, 1])).toString()));
    const nativeFindings = (expected.findings as { rule_id: string; finding_id: string }[]);
    assert.ok(nativeFindings.some(item => item.rule_id === findings[0].code));
    assert.deepEqual(await readFile(file), before);

    const actions = await vscode.commands.executeCommand<vscode.CodeAction[]>("vscode.executeCodeActionProvider", vscode.Uri.file(file), findings[0].range);
    const explain = actions?.find(action => action.title === "Fortress: Explain finding")?.command;
    assert.equal(explain?.command, "fortress.explain");
    const explanation = await inspectText("Fortress explanation", execute("explain", explain?.arguments?.[0]));
    const explanationData = object(explanation.response.result?.data);
    assert.ok(nativeFindings.some(item => item.finding_id === explanationData.selector));
    assert.ok(page(explanationData.evidence).total > 0);

    const independent = await execute("recheck", { root: second.uri.toString() });
    assert.notEqual(independent.actual_source_ref, observed.actual_source_ref);
    assert.equal(vscode.languages.getDiagnostics(vscode.Uri.joinPath(second.uri, "src/lib.rs")).filter(item => item.source === "Fortress").length, 0);
    assert.equal(vscode.languages.getDiagnostics(vscode.Uri.file(file)).filter(item => item.source === "Fortress").length, findings.length);

    const proposal = await execute("author", { ...selected, module: fixtureModule, target: "filesystem.read", disposition: "ALLOW" });
    assert.equal(object(proposal.result?.data).classification, "PROPOSED");
    assert.match(vscode.window.activeTextEditor?.document.getText() ?? "", /UNAPPROVED|Review required/);

    const editor = await vscode.window.showTextDocument(vscode.Uri.file(file));
    const updated = "// unchanged file encoding\npub fn value() {}\n";
    await editor.edit(edit => edit.replace(new vscode.Range(editor.document.positionAt(0),
        editor.document.positionAt(editor.document.getText().length)), updated));
    assert.equal(editor.document.isDirty, true);
    const { view: previewText, response: result } = await inspectText("Fortress hypothetical proposal", execute("previewBuffer", selected));
    assert.match(previewText, /PROPOSED.*Unapplied/);
    const view = object(result.result?.data);
    const previewRows = page(view.evidence);
    assert.ok(previewRows.total > 0);
    assert.deepEqual(await readFile(file), before);
    assert.equal(editor.document.isDirty, true);
    assert.ok(await editor.document.save());
    assert.equal(vscode.languages.getDiagnostics(vscode.Uri.file(file)).filter(item => item.source === "Fortress").length, 0);
    // Allow the fixture's native watcher event to settle independently of the document save event.
    await new Promise(resolve => setTimeout(resolve, 500));
    const stale = await execute("refresh", selected);
    assert.equal(stale.source_freshness, "STALE");
    assert.equal(stale.selected_source_ref, observed.actual_source_ref);
    const rechecked = await execute("recheck", selected);
    assert.equal(rechecked.source_freshness, "FRESH");
    assert.notEqual(rechecked.actual_source_ref, observed.actual_source_ref);
    assert.equal(vscode.languages.getDiagnostics(vscode.Uri.file(file)).filter(item => item.source === "Fortress").length, 0);
    await vscode.commands.executeCommand("fortress.close", selected);
    assert.equal((await execute("status", { root: second.uri.toString() })).actual_source_ref, independent.actual_source_ref);
    await vscode.commands.executeCommand("fortress.close", { root: second.uri.toString() });
    await writeFile(report, JSON.stringify({
        status: "PASS", os: process.platform, arch: process.arch, vscode: vscode.version,
        protocol: observed.protocol_version, original_source: observed.actual_source_ref,
        updated_source: rechecked.actual_source_ref, diagnostics: findings.length,
        projection_rows: previewRows.total, diagnostic_startup_ms: startup
    }, null, 2));
}
