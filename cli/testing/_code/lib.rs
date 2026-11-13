//! Explicit Cargo test crate root for private CLI adapter boundary controls.
#[path = "../../_code/diagnostics.rs"]
mod diagnostics;
#[path = "../../_code/verifier_process.rs"]
mod verifier_process;

mod diagnostic_controls;
mod verifier_process_controls;
