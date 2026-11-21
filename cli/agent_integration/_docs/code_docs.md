# Code

## Role

This Module translates agent requests and independently reviewed local invocations into existing Fortress interfaces.

## Execution

**Local agent transport**

Launch an installed, independently selected Fortress binary with arguments `serve --mcp /absolute/repository`. The host should configure the binary and repository path outside candidate-controlled settings. The server reads one UTF-8 JSON-RPC message per line and emits only protocol messages on stdout. It offers MCP editions `2025-11-25` and `2025-06-18`. For a different requested edition it proposes its latest supported version. A client that cannot use the proposed edition should disconnect.

An example session sends each line after receiving the preceding reply where applicable.

~~~json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"local-client","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fortress_inspect","arguments":{"request":{"protocol_version":1,"request_id":"capabilities","method":"capabilities","parameters":{}}}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fortress_inspect","arguments":{"request":{"protocol_version":5,"request_id":"status","method":"status","parameters":{}}}}}
~~~

`fortress_inspect` returns the unmodified native result as `structuredContent`, with the same JSON in a text item for consumers that render content blocks. The loaded snapshot and its selected evidence keep separate identities. Use native capabilities before requesting optional methods. Pass native state and context references and exact continuation cursors when paging. Supply original-state and proposal inputs through explicit host startup options where needed. These remain immutable observations. Ordinary inspection has no analysis or project execution side effect.

To enable explicit candidate analysis, also supply `--candidate-storage /absolute/external-directory`. This enables `fortress_candidate_base` to return the exact physical base and context and `fortress_evaluate_candidate` to consume a native CandidateRequest. Use the base tool first, then send exact migration operations with preimages and proposed postimages in `request`. A stale base requires a new session and re-evaluation. Supported evaluation uses existing SESSION/OVERLAY admission and fallback. It returns an inline `PROPOSED` record or an explicit resource error. Use the native overlay command and preloaded candidate paging when a full record exceeds the inline limit. The service retains at most one prepared candidate workspace and releases each candidate buffer after evaluation. It writes no proposal or source through MCP.

**Trusted local invocation**

An independent embedding can call `fortress_cli::mediator::TrustedMediator`. It constructs the mediator with the host's absolute physical repository root, pinned trust epoch, independently selected `TrustedBasePolicy`, external `GrantValidator`, invocation authority and external OPS storage. The application and recovery entry points are available only through this in-process port. The public MCP entry point has no connection to any of these trusted inputs.

Use `preview` to obtain the exact MigrationPlan. A trusted operator or approval mechanism reviews that precise plan and binds a one-use invocation to the native repository identity, host trust epoch, digest and action. The `InvocationAuthority` must authenticate that independent approval, claim it atomically and recheck it at use time within a bounded deadline. Its durable replay control lives outside user repositories and persists across restart. Configuration and grants are selected independently of the candidate. The mediator revalidates each admitted scoped grant and checks expiration before source-changing boundaries. A serialized plan, approval-shaped record or completed receipt provides no invocation or grant.

The embedding calls `apply` with the reviewed plan and cancellation flag. The canonical authority receives the existing protected-grant decisions and checks original evaluator, scope, source, policy and required assurance. The migration engine reobserves the physical repository, verifies exact preimages and evaluated target, acquires its own writer lease, and publishes a receipt only after actual-state verification. First-intent, finding-maintenance and ungoverned workflows keep their existing dedicated routes. Supported local write operations cover regular file create, replace, relocation and owned deletion through the existing operation graph.

If interruption allocates a transaction, preserve its journal and report the transaction reference. An authenticated recovery review identifies the original plan and exact transaction and chooses resume or rollback. Resume uses the existing authority revalidation. The writer restores only known preimages or removes exclusively owned postimages. Independent changes remain conflicts. Concurrent Fortress writers rely on the same machine-local OPS lease. Other local writers and processes remain outside this integration's control.

The reproducible controlled example is the `exact_review_and_protected_grants_are_required_before_real_writes` test. It attempts a protected contract replacement without a reviewed invocation and without a scoped grant, verifies byte preservation twice, then provides an independent test-only review and bound grant. The real writer applies and reobserves the target. Run `cargo +1.97.1 --config _data/cargo_config.toml test --manifest-path _data/Cargo.toml -p fortress-cli --test agent_integration` from the source root. The fixture validator is linked only into the test; an application must supply its own independently authenticated port.

**External providers**

The GitHub rules observer consumes selected GitHub REST branch identity and active-rule pages through a read-only authenticated embedding. It requires stable repository identity, exact branch and exact head around two matching bounded rule observations. It returns rule digests and types without payload strings or credentials. The optional `GitHubCliRead` implementation uses an independently installed absolute GitHub CLI with a pinned binary digest, a host-owned configuration directory, and a host-supplied read credential. It issues only fixed GitHub.com GET operations. Its credential stays out of process arguments and reports.

## State

The adapter retains immutable results and one optional candidate workspace per connection. Trusted write state stays in the migration writer.

Documented requirements, observed configuration, actual per-actor enforcement, independent proposal authorization and local writer coverage are reported separately. Production branch enforcement remains `UNVERIFIED`. GitHub pull-request review metadata alone does not bind an exact Fortress proposal, protected scope, issuer policy, validity period or separately qualified assessor. No provider settings are changed.

The host-capability manifest describes only the named routes available in the exact build. Direct Codex app-server filesystem commands, shell operations, editor writes and other OS access are outside the mediator. Codex clients can consume read-only MCP. An external enforceable sandbox or trusted native route would require separate exact-host coverage evidence.

## Failure Semantics

The connection permits up to 65,536 bytes per input frame, 2 MiB per output frame, eight active work requests, 4,096 unique request IDs, and 8,192 total frames. An oversized unterminated input closes the connection at the discard bound. Output oversize is an error. One worker executes accepted work in order. MCP `notifications/cancelled` target the outer JSON-RPC request ID. Cancellation is cooperative, including before and after explicit initial analysis work, and disconnect retires the connection's request state. Bounded backpressure applies when the client stops reading. Start one server process per connection. The adapter exposes no network listener, project commands, issuer credentials, or source-changing methods. Child agents can use the same read-only contract if granted a connection by their own host.

## Files

### [`capabilities.rs`](../_code/capabilities.rs)

Reports the available interfaces and the limits of each route.

### [`github.rs`](../_code/github.rs)

Observes bounded GitHub branch rules for the independently selected target.

### [`mcp.rs`](../_code/mcp.rs)

Implements MCP stdio negotiation, framing and dispatch to existing inspection and candidate APIs.

### [`mcp_wire.rs`](../_code/mcp_wire.rs)

Owns bounded framing, request correlation, negotiation, cancellation and queued-work admission.

### [`mediator.rs`](../_code/mediator.rs)

Routes exact independently reviewed operations through the migration writer and recovery interface.

### [`verifier_process.rs`](../_code/verifier_process.rs)

Selects an absolute host Python outside the working and bundle trees, then supervises the installed isolated offline consumer with bounded output, an execution deadline and owned-child kill/reap on failure. Trusted host tool selection is separate from repository declarations and does not authenticate producer evidence.

GitHub CLI requests use the same supervisor with a pinned executable digest and a scoped, shorter deadline.
