# Code

## Role

The editor adapter translates editor lifecycle events into bounded requests against Fortress's published read-only interfaces.

## Execution

Run `python -B editor/_code/build.py <new-external-directory> --install-tools --vsix` with Python 3.11+, Node 22+, and npm. The staged output stays outside the repository. Install the VSIX with `code --install-extension <path-to-fortress-development.vsix>`. Set `fortress.executable` in local User Settings to the absolute path of an installed Fortress binary outside all opened repository folders.

The initial qualified editor is VS Code Desktop 1.147.0 on Windows x64 and Linux x64. The desktop harness exercised Windows 11 and Ubuntu. The manifest declares VS Code API 1.100 as the minimum API version needed to load the adapter.

Open a trusted local repository, then run **Fortress: Refresh Saved-Source Status**. Choose a folder in a multi-root window. Use **Doctor** to inspect missing inputs and **Browse Findings** to choose a governing Module, explanation, or verified source position. Problems links are backed by the observed source file digest. Use the **Fortress: Explain finding** code action from a diagnostic. **Inspect Architecture and Policy** shows exact Module identities, outgoing routes, incoming dependents, and recorded relationships.

Use **Recheck Saved Source** for explicit static evaluation without full certification. **Preview Policy and Schema Guidance** uses the installed authoring facade. **Preview Unsaved Buffer** converts one supported UTF-8 buffer into an exact replace operation and invokes OVERLAY with an owned temporary request file. Save edits through the editor independently, then recheck. **Compare Saved States** uses explicit saved observations or existing complete comparison inputs. Close inspection to release its process and retained temporary inputs.

## State

Stdio negotiation starts with protocol v1 and selects the highest mutually advertised edition through v5. Separate capabilities control optional features. Queries pin state and context; continuations are opaque and tied to the service incarnation. Paging shows every recorded row within user-selected pages. Diagnostic publication has a separate visible 500-row limit. Native views render bounded plain text. Source and evidence strings receive display-only escaping for control characters, theme icons and links. Requests retain the original canonical identities.

## Failure Semantics

Filesystem and branch notifications invalidate loaded state and clear diagnostics. Refresh reobserves source bytes. Unsupported, stale, ambiguous, missing and incomplete evidence stays visible. Unspecified column units yield a precise range only where UTF-8, Unicode scalar and UTF-16 interpretations agree. Older installed services may lack optional inventories. A cancelled or failed preview conveys no permission or actual-state verdict. If startup fails, inspect the local Fortress Output channel, verify the absolute executable and Workspace Trust settings, then refresh.

## Files

### [`build.py`](../_code/build.py)

Stages the development extension and locked TypeScript toolchain outside governed source. The VSIX contains runtime JavaScript and installation metadata.

### [`extension.ts`](../_code/extension.ts)

Owns native status, diagnostics, menus, plaintext views, explicit preview commands, and per-workspace lifecycle registration.

### [`source.ts`](../_code/source.ts)

Validates portable paths and file bytes, converts defensible source spans, sanitizes display text, and tracks invalidation generations.

### [`transport.ts`](../_code/transport.ts)

Owns bounded stdio framing, capability negotiation, active-request correlation, cancellation, and child lifetime.

### [`workspace.ts`](../_code/workspace.ts)

Owns user-selected process admission and exact immutable inputs for repository inspection, saved-state recheck, and unsaved OVERLAY preview.
