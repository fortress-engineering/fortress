//! Owning Testing Element controls over the existing private implementation.
use super::*;

/// `T-TF-CLI-0001-R29-005`
/// Fortress requirement: TF-CLI-0001-R29
#[test]
fn split_and_invalid_utf8_diagnostics_remain_safe_and_bounded() {
    let mut output = Vec::new();
    let mut writer = DiagnosticWriter::new(&mut output);
    for byte in "safe é \u{202e}\u{1b}\r".as_bytes() {
        writer.write_all(&[*byte]).unwrap();
    }
    writer.write_all(&[255, 0xe2]).unwrap();
    writer.flush().unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(text.starts_with("safe é "));
    assert!(!text.contains('\u{202e}'));
    assert!(!text.contains('\u{1b}'));
    assert!(text.ends_with("\\xff\\xe2"));
}
