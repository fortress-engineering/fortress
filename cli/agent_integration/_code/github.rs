//! GitHub active-rule observation, separate from local mediation and grant issuance.

use fortress_core::wire::{canonicalize_public_json, parse_public_json};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;

const MAX_PAGE_BYTES: usize = 1024 * 1024;
const MAX_PAGES: u16 = 8;

/// Pinned version of the GitHub REST fields consumed by this adapter.
pub const API_VERSION: &str = "2026-03-10";

/// Independently selected GitHub repository, reference and exact head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BranchIdentity {
    /// Immutable numeric GitHub repository identity, not a mutable slug.
    pub repository_id: u64,
    /// Exact protected branch, without the refs/heads prefix.
    pub branch: String,
    /// Exact observed Git commit.
    pub head: String,
}

/// Response from one authenticated active branch-rule read.
pub struct RulePage {
    /// Rule list as received from the fixed GitHub REST endpoint.
    pub body: Vec<u8>,
    /// Next validated page number, if GitHub reports another page.
    pub next_page: Option<u16>,
}

/// Failure of the separately configured provider read boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderFailure {
    /// Network, timeout or remote service failure.
    Unavailable,
    /// Request cannot be made or verified using the configured scope.
    InsufficientPermission,
    /// A complete response could not be established.
    Incomplete,
}

/// Independently authenticated, bounded read port for a preselected GitHub target.
///
/// The embedding selects the repository, API base, installed client and credential
/// outside the repository. This port uses only GET operations and returns no tokens,
/// request headers, URLs from payloads, or reviewer text. A fixture implementation
/// does not qualify production provider protection.
pub trait GitHubRulesRead {
    /// Reads the repository id and branch head from the selected repository and ref.
    ///
    /// # Errors
    /// Fails when either identity cannot be verified by the configured provider.
    fn branch_identity(&self) -> Result<BranchIdentity, ProviderFailure>;

    /// Reads a numbered page from GitHub's active rules for the exact selected branch.
    ///
    /// # Errors
    /// Fails on an unverified response, opaque continuation or missing authority.
    fn rules_page(&self, page: u16) -> Result<RulePage, ProviderFailure>;
}

/// Independently observed branch rules, separate from per-principal enforcement.
#[derive(Debug, Serialize)]
pub struct GitHubRulesObservation {
    /// Edition of the adapter's report.
    pub schema_version: u16,
    /// API contract revision used to interpret the response.
    pub api_version: &'static str,
    /// Selected exact target.
    pub target: BranchIdentity,
    /// State of verified configuration evidence.
    pub configuration_status: &'static str,
    /// Canonical identities of active returned rule records.
    pub active_rule_refs: Vec<String>,
    /// Types of the active rules, including unrecognized provider types.
    pub rule_types: Vec<String>,
    /// Reason evidence could not be consumed, when applicable.
    pub unavailable: Option<ProviderFailure>,
    /// Effective write enforcement for a particular actor remains unverified.
    pub write_enforcement: &'static str,
    /// These configuration observations cannot authenticate a Fortress proposal grant.
    pub proposal_authorization: &'static str,
}

/// Observes active provider rules for the exact selected branch and Git head.
///
/// Empty, inaccessible, stale or inconsistent observations supply no permission.
/// GitHub pull-request approvals and rules are not exact Fortress grant assertions.
#[must_use]
pub fn observe_rules(
    target: &BranchIdentity,
    read: &impl GitHubRulesRead,
) -> GitHubRulesObservation {
    let mut result = GitHubRulesObservation {
        schema_version: 1,
        api_version: API_VERSION,
        target: target.clone(),
        configuration_status: "UNVERIFIED",
        active_rule_refs: Vec::new(),
        rule_types: Vec::new(),
        unavailable: None,
        write_enforcement: "UNVERIFIED",
        proposal_authorization: "NONE",
    };
    match collect(target, read).and_then(|first| {
        first.map_or(Ok((None, None)), |first| {
            collect(target, read).map(|second| (Some(first), second))
        })
    }) {
        Ok((Some(first), Some(second))) if first == second => {
            let (references, types) = first;
            result.configuration_status = "ACTIVE_RULES_OBSERVED";
            result.active_rule_refs = references.into_iter().collect();
            result.rule_types = types.into_iter().collect();
        }
        Ok((Some(_), Some(_))) => result.configuration_status = "CONFIGURATION_CHANGED",
        Ok(_) => result.configuration_status = "TARGET_CHANGED",
        Err(error) => result.unavailable = Some(error),
    }
    result
}

type ActiveRules = (BTreeSet<String>, BTreeSet<String>);

fn collect(
    target: &BranchIdentity,
    read: &impl GitHubRulesRead,
) -> Result<Option<ActiveRules>, ProviderFailure> {
    if target.repository_id == 0
        || target.repository_id > (1_u64 << 53) - 1
        || target.branch.is_empty()
        || target.branch.len() > 255
        || target.branch.chars().any(char::is_control)
        || target.head.len() != 40
        || !target
            .head
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProviderFailure::Incomplete);
    }
    if read.branch_identity()? != *target {
        return Ok(None);
    }
    let mut references = BTreeSet::new();
    let mut types = BTreeSet::new();
    for page in 1..=MAX_PAGES {
        let response = read.rules_page(page)?;
        if response.body.len() > MAX_PAGE_BYTES {
            return Err(ProviderFailure::Incomplete);
        }
        let text = std::str::from_utf8(&response.body).map_err(|_| ProviderFailure::Incomplete)?;
        let records: Vec<Value> =
            parse_public_json(text).map_err(|_| ProviderFailure::Incomplete)?;
        if records.len() > 100 || records.is_empty() && response.next_page.is_some() {
            return Err(ProviderFailure::Incomplete);
        }
        for record in records {
            let kind = record
                .get("type")
                .and_then(Value::as_str)
                .filter(|kind| {
                    !kind.is_empty()
                        && kind.len() <= 128
                        && kind.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                        })
                })
                .ok_or(ProviderFailure::Incomplete)?;
            let canonical = canonicalize_public_json(&record.to_string())
                .map_err(|_| ProviderFailure::Incomplete)?;
            if !references.insert(fortress_core::portable::digest(&canonical)) {
                return Err(ProviderFailure::Incomplete);
            }
            types.insert(kind.into());
        }
        match response.next_page {
            Some(next) if next == page + 1 && next <= MAX_PAGES => {}
            Some(_) => return Err(ProviderFailure::Incomplete),
            None => {
                return if read.branch_identity()? == *target {
                    Ok(Some((references, types)))
                } else {
                    Ok(None)
                };
            }
        }
    }
    Err(ProviderFailure::Incomplete)
}

/// Host-selected GitHub.com repository coordinates. They are never taken from an agent.
pub struct CliSelection {
    /// GitHub repository owner.
    pub owner: String,
    /// GitHub repository name.
    pub repository: String,
    /// Exact branch name, without the refs/heads prefix.
    pub branch: String,
}

/// Read-only GitHub.com transport using a pinned, independently installed GitHub CLI.
///
/// Construction does not contact GitHub. Calls use the supplied read credential
/// in a child-only environment and fixed GET routes. No credential is serialized.
pub struct GitHubCliRead {
    tool: std::path::PathBuf,
    tool_ref: String,
    config_directory: std::path::PathBuf,
    config_identity: fortress_core::heavy_admission::DirectoryIdentity,
    selection: CliSelection,
    credential: std::ffi::OsString,
}

impl GitHubCliRead {
    /// Configures the exact read boundary. The executable and configuration directory
    /// must be host-owned and outside the inspected repository.
    ///
    /// # Errors
    /// Rejects unavailable credentials, malformed names, links, paths inside the
    /// inspected repository, or missing configuration.
    pub fn from_host(
        inspected_repository: &std::path::Path,
        tool: &std::path::Path,
        tool_ref: &str,
        config_directory: &std::path::Path,
        selection: CliSelection,
        credential: std::ffi::OsString,
    ) -> Result<Self, ProviderFailure> {
        use fortress_core::heavy_admission::DirectoryIdentity;
        if credential.is_empty() {
            return Err(ProviderFailure::InsufficientPermission);
        }
        if !tool.is_absolute()
            || !config_directory.is_absolute()
            || !tool_ref.strip_prefix("sha256:").is_some_and(|hex| {
                hex.len() == 64
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
            || !component(&selection.owner)
            || !component(&selection.repository)
            || selection.branch.is_empty()
            || selection.branch.len() > 255
            || selection.branch.chars().any(char::is_control)
            || selection
                .branch
                .split('/')
                .any(|part| matches!(part, "" | "." | ".."))
        {
            return Err(ProviderFailure::Incomplete);
        }
        let protected = inspected_repository
            .canonicalize()
            .map_err(|_| ProviderFailure::Incomplete)?;
        let tool = tool
            .canonicalize()
            .map_err(|_| ProviderFailure::Incomplete)?;
        let config_identity = DirectoryIdentity::capture(config_directory)
            .map_err(|_| ProviderFailure::Incomplete)?;
        let config_directory = config_directory
            .canonicalize()
            .map_err(|_| ProviderFailure::Incomplete)?;
        if !crate::verifier_process::outside_inputs(&tool, &[&protected]).unwrap_or(false)
            || !crate::verifier_process::outside_inputs(&config_directory, &[&protected])
                .unwrap_or(false)
            || config_directory == protected
            || config_directory.starts_with(&protected)
        {
            return Err(ProviderFailure::Incomplete);
        }
        #[cfg(windows)]
        if !tool
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
        {
            return Err(ProviderFailure::Incomplete);
        }
        Ok(Self {
            tool,
            tool_ref: tool_ref.into(),
            config_directory,
            config_identity,
            selection,
            credential,
        })
    }

    fn endpoint(&self) -> String {
        format!(
            "repos/{}/{}",
            self.selection.owner, self.selection.repository
        )
    }

    fn get(&self, endpoint: &str) -> Result<RulePage, ProviderFailure> {
        use std::process::Command;
        use std::time::Duration;
        if !self
            .config_identity
            .matches(&self.config_directory)
            .unwrap_or(false)
        {
            return Err(ProviderFailure::Incomplete);
        }
        let mut command = Command::new(&self.tool);
        command
            .env_clear()
            .env("GH_TOKEN", &self.credential)
            .env("GH_CONFIG_DIR", &self.config_directory)
            .env("GH_PROMPT_DISABLED", "1")
            .env("NO_COLOR", "1")
            .current_dir(&self.config_directory);
        #[cfg(windows)]
        if let Some(system) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system);
        }
        command
            .args([
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
                "--include",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
            ])
            .arg(format!("X-GitHub-Api-Version: {API_VERSION}"))
            .arg(endpoint);
        let (bytes, exit) =
            crate::verifier_process::run_pinned(command, Duration::from_secs(15), &self.tool_ref)
                .map_err(|_| ProviderFailure::Unavailable)?;
        if !self
            .config_identity
            .matches(&self.config_directory)
            .unwrap_or(false)
        {
            return Err(ProviderFailure::Incomplete);
        }
        decode_cli_response(&bytes, exit)
    }
}

impl GitHubRulesRead for GitHubCliRead {
    fn branch_identity(&self) -> Result<BranchIdentity, ProviderFailure> {
        let endpoint = self.endpoint();
        let repository = self.get(&endpoint)?.json()?;
        let expected_slug = format!("{}/{}", self.selection.owner, self.selection.repository);
        if !repository["full_name"]
            .as_str()
            .is_some_and(|actual| actual.eq_ignore_ascii_case(&expected_slug))
        {
            return Err(ProviderFailure::Incomplete);
        }
        let branch = self
            .get(&format!(
                "{endpoint}/branches/{}",
                encode(&self.selection.branch)
            ))?
            .json()?;
        if branch["name"] != self.selection.branch {
            return Err(ProviderFailure::Incomplete);
        }
        Ok(BranchIdentity {
            repository_id: repository["id"]
                .as_u64()
                .ok_or(ProviderFailure::Incomplete)?,
            branch: self.selection.branch.clone(),
            head: branch["commit"]["sha"]
                .as_str()
                .ok_or(ProviderFailure::Incomplete)?
                .into(),
        })
    }

    fn rules_page(&self, page: u16) -> Result<RulePage, ProviderFailure> {
        if !(1..=MAX_PAGES).contains(&page) {
            return Err(ProviderFailure::Incomplete);
        }
        let response = self.get(&format!(
            "{}/rules/branches/{}?per_page=100&page={page}",
            self.endpoint(),
            encode(&self.selection.branch)
        ))?;
        if response.next_page.is_some_and(|next| next != page + 1) {
            return Err(ProviderFailure::Incomplete);
        }
        Ok(RulePage {
            body: response.body,
            next_page: response.next_page,
        })
    }
}

fn component(name: &str) -> bool {
    !matches!(name, "" | "." | "..")
        && name.len() <= 100
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn encode(branch: &str) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(branch.len());
    for byte in branch.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.".contains(&byte) {
            result.push(char::from(byte));
        } else {
            write!(&mut result, "%{byte:02X}").expect("writing to String");
        }
    }
    result
}

impl RulePage {
    fn json(&self) -> Result<Value, ProviderFailure> {
        let text = std::str::from_utf8(&self.body).map_err(|_| ProviderFailure::Incomplete)?;
        parse_public_json(text).map_err(|_| ProviderFailure::Incomplete)
    }
}

/// Decodes a bounded HTTP envelope from the pinned GitHub CLI read route.
///
/// It retains the body and, where present, a bounded numeric page parameter.
/// The caller still checks the exact repository, branch and stable rules.
///
/// # Errors
/// Returns a typed failure for malformed, unsupported or failed responses.
pub fn decode_cli_response(bytes: &[u8], exit: u8) -> Result<RulePage, ProviderFailure> {
    let text = std::str::from_utf8(bytes).map_err(|_| ProviderFailure::Incomplete)?;
    let (headers, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or(ProviderFailure::Incomplete)?;
    let mut lines = headers.lines();
    match lines
        .next()
        .and_then(|line| line.strip_prefix("HTTP/"))
        .and_then(|line| line.split_ascii_whitespace().nth(1))
    {
        Some("200") if exit == 0 => {}
        Some("401" | "403" | "404") => return Err(ProviderFailure::InsufficientPermission),
        Some("429" | "500" | "502" | "503" | "504") => return Err(ProviderFailure::Unavailable),
        _ => return Err(ProviderFailure::Incomplete),
    }
    let mut next_page = None;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            return Err(ProviderFailure::Incomplete);
        };
        if key.eq_ignore_ascii_case("link") {
            for link in value.split(',') {
                let (url, relation) = link.split_once(';').ok_or(ProviderFailure::Incomplete)?;
                if relation.trim() == "rel=\"next\"" {
                    let value = url
                        .trim()
                        .strip_prefix("<https://api.github.com/")
                        .and_then(|url| url.strip_suffix('>'))
                        .and_then(|url| url.split_once('?'))
                        .and_then(|(_, query)| {
                            query
                                .split('&')
                                .find_map(|parameter| parameter.strip_prefix("page="))
                        })
                        .and_then(|number| number.parse::<u16>().ok())
                        .ok_or(ProviderFailure::Incomplete)?;
                    if next_page.replace(value).is_some() {
                        return Err(ProviderFailure::Incomplete);
                    }
                }
            }
        }
    }
    Ok(RulePage {
        body: body.as_bytes().into(),
        next_page,
    })
}
