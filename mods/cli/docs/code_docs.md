# CLI Code

`command.rs` owns the stable built-in command registry. `lib.rs` dispatches and
renders commands without embedding provider-independent standard semantics.
`main.rs` is the native process boundary.
