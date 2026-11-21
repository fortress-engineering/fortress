# Code

### [Host tests](../_code/host.rs)

Runs the installed MCP executable on a disposable repository. It checks native status parity, exact candidate preview, replay, malformed input, session renewal and refusal of public write requests. A registered Cargo build script stays unexecuted.

The local mediator fixture supplies exact review and grant facts through the trusted ports. It checks byte preservation when required authorization is missing, when original policy prohibits a proposed write, and when a candidate tries to install a forged evidence selection. A separately reviewed edit proceeds with unrelated effect uncertainty intact. The tests also cover actual target divergence, revocation after mutation, and fresh review for rollback.

The provider fixture exercises exact branch identity, unavailable and incomplete configuration, and drifting branch rules. These tests use locally established observations and confer no production provider coverage.

### [MCP controls](../_code/mcp_controls.rs)

Checks cancellation correlation and bounded termination of incomplete input.

### [GitHub controls](../_code/github_controls.rs)

Checks response decoding through bounded pagination and refusal of unsupported link targets.
