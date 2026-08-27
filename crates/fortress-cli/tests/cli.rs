//! Process-level evidence for the canonical Fortress CLI entrypoints.

use std::process::{Command, Output};

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fortress"))
        .args(arguments)
        .output()
        .expect("Fortress CLI process must start")
}

/// `T-TF-CLI-0001-R03-001`
#[test]
fn version_flag_reports_implementation_identity() {
    let output = run(&["--version"]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "fortress 0.1.0\n");
    assert!(output.stderr.is_empty());
}

/// `T-TF-CLI-0001-R03-002`
#[test]
fn help_discovers_only_implemented_commands() {
    let output = run(&["help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("help"));
    assert!(stdout.contains("version"));
    assert!(
        !stdout
            .lines()
            .any(|line| line.trim_start().starts_with("audit "))
    );
    assert!(
        !stdout
            .lines()
            .any(|line| line.trim_start().starts_with("certify "))
    );
}

/// `T-TF-CLI-0001-R03-003`
#[test]
fn unsupported_certification_command_fails() {
    let output = run(&["certify"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported command `certify`"));
}

/// `T-TF-CLI-0001-R03-004`
#[test]
fn version_rejects_extra_arguments() {
    let output = run(&["--version", "unexpected"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage: fortress --version"));
}
