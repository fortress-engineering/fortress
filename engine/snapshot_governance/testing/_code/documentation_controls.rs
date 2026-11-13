//! Owning Testing Element controls over the existing private implementation.
use super::*;

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-008`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn patched_wikilinks_do_not_amplify_sibling_events() {
    let source = "[[a|]] ".repeat(16);
    let count = Parser::new_ext(&source, Options::all()).count();
    assert_eq!(count, 65);
    assert!(MarkdownDocument::parse(&source).is_ok());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-009`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn nested_image_wikilinks_and_oversized_markdown_have_explicit_bounds() {
    let source = format!("{}text{}", "![[".repeat(256), "]]".repeat(256));
    assert!(MarkdownDocument::parse(&source).is_ok());
    assert!(MarkdownDocument::parse(&"x".repeat(4 * 1024 * 1024 + 1)).is_err());
}
