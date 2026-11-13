//! Candidate-owned executable selection is never portable verification authority.
use std::fs;
use std::process::Command;

/// `T-TF-CLI-0001-R29-003`
/// Fortress requirement: TF-CLI-0001-R29
#[test]
fn candidate_interpreter_assertions_cannot_execute_a_repository_tool() {
    let root = std::env::temp_dir().join(format!("fortress-tool-shadow-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let tool = root.join(if cfg!(windows) {
        "python.exe"
    } else {
        "python3"
    });
    fs::write(&tool, b"untrusted executable: must not be invoked").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fortress"))
        .current_dir(&root)
        .env("FORTRESS_VERIFIER_PYTHON", &tool)
        .env("PATH", &root)
        .args([
            "bundle",
            "verify",
            ".",
            "--predicate-type",
            "https://example.invalid/fortress/v1",
        ])
        .output()
        .unwrap();
    fs::remove_dir_all(&root).unwrap();
    assert!(!output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "VERIFIER_UNAVAILABLE");
}

/// `T-TF-CLI-0001-R29-004`
/// Fortress requirement: TF-CLI-0001-R29
#[test]
fn untrusted_error_fields_cannot_execute_terminal_controls() {
    let mut output = Vec::new();
    let mut error = Vec::new();
    let code = fortress_cli::run(["bad\u{1b}[2J\r\u{202e}"], &mut output, &mut error).unwrap();
    assert_ne!(code, 0);
    let error = String::from_utf8(error).unwrap();
    assert!(!error.contains('\u{1b}'));
    assert!(!error.contains('\r'));
    assert!(!error.contains('\u{202e}'));
    assert!(error.contains("\\u{1b}"));
}
