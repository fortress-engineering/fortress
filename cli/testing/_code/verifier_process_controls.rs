//! Owning Testing Element controls over the existing private implementation.
use crate::verifier_process::{self, interpreter, run_bounded};
use std::process::Command;
use std::time::Duration;

fn python() -> Command {
    let interpreter = interpreter(&std::env::temp_dir()).expect("trusted host Python");
    let mut command = Command::new(interpreter);
    command.args(["-I", "-B", "-"]);
    command
}

/// `T-TF-CLI-0001-R29-001`
/// Fortress requirement: TF-CLI-0001-R29
#[test]
fn embedded_consumer_supervision_rejects_expanding_output() {
    let (output, status) = verifier_process::run(python(), "print(1)\n").unwrap();
    assert_eq!(status, 0);
    assert_eq!(String::from_utf8(output).unwrap().trim(), "1");
    let error = run_bounded(
        python(),
        "import sys\nsys.stdout.write('x' * 2000000)\n",
        Duration::from_mins(3),
    )
    .unwrap_err();
    assert_eq!(error.code, "RESOURCE_LIMIT");
}

/// `T-TF-CLI-0001-R29-002`
/// Fortress requirement: TF-CLI-0001-R29
#[test]
fn embedded_consumer_deadline_kills_and_reaps_owned_child() {
    let error = run_bounded(
        python(),
        "import time\ntime.sleep(60)\n",
        Duration::from_millis(100),
    )
    .unwrap_err();
    assert_eq!(error.code, "RESOURCE_LIMIT");
}
