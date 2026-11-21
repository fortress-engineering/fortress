//! Focused private controls for the installed agent boundary.

use fortress_cli::github_rules::{ProviderFailure, decode_cli_response};

/// `T-TF-AGENT-INTEGRATION-0001-R03-002`
/// Fortress requirement: TF-AGENT-INTEGRATION-0001-R03
#[test]
fn github_cli_http_envelope_is_bounded_and_does_not_follow_link_targets() {
    let good = b"HTTP/2.0 200 OK\r\nLink: <https://api.github.com/repositories/8/rules/branches/main?page=2>; rel=\"next\"\r\n\r\n[]";
    let response = decode_cli_response(good, 0).unwrap();
    assert_eq!(response.next_page, Some(2));
    assert_eq!(response.body, b"[]");
    let invalid =
        b"HTTP/2.0 200 OK\nLink: <https://not-provider.example/?page=2>; rel=\"next\"\n\n[]";
    assert_eq!(
        decode_cli_response(invalid, 0).err(),
        Some(ProviderFailure::Incomplete)
    );
    assert_eq!(
        decode_cli_response(b"HTTP/2.0 403 Forbidden\n\n{}", 1).err(),
        Some(ProviderFailure::InsufficientPermission)
    );
}
