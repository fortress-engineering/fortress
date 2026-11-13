//! Adversarial Markdown controls through the existing public documentation evaluator.
use fortress_core::documentation::evaluate_documentation_files;
use pulldown_cmark::{Options, Parser};
use std::collections::BTreeMap;

fn evaluate(source: &str) -> fortress_core::documentation::DocumentationConformanceReport {
    let files = BTreeMap::from([("README.md".to_owned(), source.as_bytes().to_vec())]);
    let report = evaluate_documentation_files(&files, "1.0.0-draft.2").unwrap();
    assert_eq!(report.summary().markdown_files_inspected(), 1);
    report
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-008`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn patched_wikilinks_do_not_amplify_sibling_events() {
    let source = "[[a|]] ".repeat(16);
    let count = Parser::new_ext(&source, Options::all()).count();
    assert_eq!(count, 65);
    assert!(
        !evaluate(&source)
            .findings()
            .iter()
            .any(|f| f.violation_discriminator() == Some("MARKDOWN_RESOURCE_LIMIT"))
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-009`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn nested_image_wikilinks_and_oversized_markdown_have_explicit_bounds() {
    let source = format!("{}text{}", "![[".repeat(256), "]]".repeat(256));
    assert!(
        !evaluate(&source)
            .findings()
            .iter()
            .any(|f| f.violation_discriminator() == Some("MARKDOWN_RESOURCE_LIMIT"))
    );
    assert!(
        evaluate(&"x".repeat(4 * 1024 * 1024 + 1))
            .findings()
            .iter()
            .any(
                |f| f.violation_discriminator() == Some("MARKDOWN_RESOURCE_LIMIT")
                    && f.message().contains("exceeds 4 MiB admission")
            )
    );
}
