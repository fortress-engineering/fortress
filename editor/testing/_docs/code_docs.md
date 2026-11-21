# Code

## Role

Tests exercise the read-only transport client and real extension workflow.

## Execution

Build the local VSIX with `python -B editor/_code/build.py <stage> --install-tools --vsix`. Run `node --test <stage>/out/testing/_code/client.js` for the client boundaries. Run `python -B editor/testing/_code/host_runner.py --editor <desktop-executable> --fortress <installed-cli> --stage <stage> --results <new-external-directory>` for the full desktop workflow. On a headless Linux test machine, pass `--xvfb` with Xvfb and xauth available.

## State

The tests own their isolated process and fixture state.

## Failure Semantics

Invalid or interrupted requests must reject without making successful results visible.

## Files

### [`client.ts`](../_code/client.ts)

Covers protocol negotiation, exact cursor use, request limits, cancellation, crashes, path admission, and source coordinate handling.

### [`host.ts`](../_code/host.ts)

Exercises actual VS Code commands, saved source diagnostic publication, proposal inspection, a buffer fix, recheck and the Restricted Mode boundary.

### [`host_runner.py`](../_code/host_runner.py)

Launches the official desktop extension test host on isolated fixtures using the packaged runtime. Qualifies trusted and restricted workspaces in separate profiles.

### [`local_adapter.rs`](../_code/local_adapter.rs)

Checks the authored desktop entrypoint, trust and executable settings, and the exact dependency lock through the canonical Cargo test registry. Runtime behavior is exercised by the separate desktop harness.
