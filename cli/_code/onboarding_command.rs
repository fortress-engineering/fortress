//! Reviewable repository adoption over the shared Snapshot and Migration Governance owners.
use fortress_core::bootstrap::{
    OnboardingMode, OnboardingOptions, OnboardingProposal, apply_repository_onboarding,
    discover_repository_onboarding, recover_repository_onboarding, review_onboarding_baseline,
};
use fortress_core::migration_governance::{MigrationRecoveryMode, NoMutationFaults};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub(super) fn run<O: Write, E: Write>(
    args: &[String],
    output: &mut O,
    errors: &mut E,
) -> io::Result<u8> {
    let result = std::thread::scope(|scope| {
        std::thread::Builder::new().name("fortress-onboarding".into()).stack_size(8*1024*1024)
            .spawn_scoped(scope, || {
                let mut bytes=Vec::new(); execute(args,&mut bytes).map(|()|bytes)
            }).map_err(|e|e.to_string())?.join().map_err(|_|"ONBOARDING_WORKER_FAILED: no result was established; inspect any retained migration journal".to_owned())?
    });
    match result {
        Ok(bytes) => {
            output.write_all(&bytes)?;
            Ok(crate::EXIT_SUCCESS)
        }
        Err(message) => {
            let code = if message.starts_with("INVALID_ARGUMENT")
                || message.starts_with("READ_ONLY_DISCOVERY")
            {
                crate::EXIT_USAGE
            } else {
                crate::EXIT_VIOLATION
            };
            writeln!(
                errors,
                "{}",
                serde_json::json!({"code":"ONBOARDING_ERROR","message":message})
            )?;
            Ok(code)
        }
    }
}
fn load(path: &str) -> Result<String, String> {
    fortress_core::bootstrap::load_onboarding_record(Path::new(path)).map_err(|e| e.to_string())
}
fn publish(
    root: &Path,
    destination: Option<&&str>,
    document: &str,
    output: &mut impl Write,
) -> Result<(), String> {
    let Some(destination) = destination else {
        return write!(output, "{document}").map_err(|e| e.to_string());
    };
    let path = Path::new(destination);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let parent = absolute
        .parent()
        .ok_or("UNSAFE_PATH: output parent unavailable")?;
    let parent = fs::canonicalize(parent).map_err(|e| e.to_string())?;
    if parent.starts_with(fs::canonicalize(root).map_err(|e| e.to_string())?) {
        return Err(
            "READ_ONLY_DISCOVERY: review output must be outside the subject repository".into(),
        );
    }
    let path = parent.join(
        absolute
            .file_name()
            .ok_or("UNSAFE_PATH: output filename unavailable")?,
    );
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(document.as_bytes())
                .map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            if load(path.to_str().ok_or("UNSUPPORTED_PATH_ENCODING")?)? == document {
                Ok(())
            } else {
                Err("IMMUTABLE_RECORD_CONFLICT: choose a new review output path".into())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}
struct OnboardingArguments<'a> {
    mode: &'a str,
    values: BTreeMap<&'a str, &'a str>,
    findings: Vec<String>,
    root: PathBuf,
    human: bool,
}
fn parse_arguments(args: &[String]) -> Result<OnboardingArguments<'_>, String> {
    let mut index = 0;
    let mode = match args.first().map(String::as_str) {
        Some("apply" | "review" | "inspect" | "recover") => {
            index = 1;
            args[0].as_str()
        }
        _ => "discover",
    };
    let mut values = BTreeMap::new();
    let mut findings = vec![];
    let mut root = None;
    while index < args.len() {
        let key = args[index].as_str();
        index += 1;
        if !key.starts_with('-') && root.is_none() {
            root = Some(PathBuf::from(key));
            continue;
        }
        if !matches!(
            key,
            "--proposal"
                | "--request"
                | "--project-id"
                | "--display-name"
                | "--mode"
                | "--format"
                | "--output"
                | "--finding"
                | "--transaction"
                | "--recovery"
                | "--module"
        ) {
            return Err(format!("INVALID_ARGUMENT: unsupported option {key}"));
        }
        let value = args
            .get(index)
            .ok_or_else(|| format!("INVALID_ARGUMENT: {key} requires a value"))?
            .as_str();
        index += 1;
        if key == "--finding" {
            findings.push(value.to_owned());
        } else if values.insert(key, value).is_some() {
            return Err(format!("INVALID_ARGUMENT: duplicate {key}"));
        }
    }
    let root = root.unwrap_or_else(|| PathBuf::from("."));
    validate_arguments(mode, &values, &findings)?;
    let human = match values.get("--format").copied().unwrap_or("json") {
        "json" => false,
        "human" => true,
        _ => return Err("INVALID_ARGUMENT: format must be json or human".into()),
    };
    Ok(OnboardingArguments {
        mode,
        values,
        findings,
        root,
        human,
    })
}
fn validate_arguments(
    mode: &str,
    values: &BTreeMap<&str, &str>,
    findings: &[String],
) -> Result<(), String> {
    let allowed: &[&str] = match mode {
        "discover" => &[
            "--request",
            "--project-id",
            "--display-name",
            "--mode",
            "--format",
            "--output",
            "--module",
        ],
        "inspect" => &["--proposal", "--format", "--output", "--module"],
        "review" => &["--proposal", "--format", "--output"],
        "apply" => &["--proposal", "--format"],
        "recover" => &["--proposal", "--format", "--transaction", "--recovery"],
        _ => &[],
    };
    if values.keys().any(|key| !allowed.contains(key)) || (mode != "review" && !findings.is_empty())
    {
        return Err(
            "INVALID_ARGUMENT: an option is not applicable to this onboarding operation".into(),
        );
    }
    if matches!(mode, "apply" | "recover") && values.contains_key("--output") {
        return Err("INVALID_ARGUMENT: actual application outputs use stdout and registered immutable records".into());
    }
    Ok(())
}
fn load_review(parsed: &OnboardingArguments<'_>) -> Result<OnboardingProposal, String> {
    let mode = parsed.mode;
    let values = &parsed.values;
    let findings = &parsed.findings;
    let root = &parsed.root;
    let proposal = if mode == "discover" {
        if values.contains_key("--proposal") || !findings.is_empty() {
            return Err(
                "INVALID_ARGUMENT: discovery accepts a request; findings require explicit review"
                    .into(),
            );
        }
        let options = if let Some(request) = values.get("--request") {
            if ["--mode", "--project-id", "--display-name"]
                .iter()
                .any(|k| values.contains_key(k))
            {
                return Err("INVALID_ARGUMENT: request and inline declaration options are mutually exclusive".into());
            }
            OnboardingOptions::from_json_str(&load(request)?).map_err(|e| e.to_string())?
        } else {
            let mode = match values.get("--mode").copied().unwrap_or("native") {
                "native" => OnboardingMode::Native,
                "canonical" => OnboardingMode::Canonical,
                _ => return Err("INVALID_ARGUMENT: mode must be native or canonical".into()),
            };
            OnboardingOptions::new(
                values.get("--project-id").map(|v| (*v).to_owned()),
                values.get("--display-name").map(|v| (*v).to_owned()),
            )
            .with_mode(mode)
        };
        discover_repository_onboarding(root, &options).map_err(|e| e.to_string())?
    } else {
        let path = values
            .get("--proposal")
            .ok_or("INVALID_ARGUMENT: --proposal is required")?;
        OnboardingProposal::from_json_str(&load(path)?).map_err(|e| e.to_string())?
    };
    Ok(proposal)
}
fn render_action(
    parsed: &OnboardingArguments<'_>,
    proposal: &OnboardingProposal,
) -> Result<String, String> {
    let mode = parsed.mode;
    let values = &parsed.values;
    let findings = &parsed.findings;
    let root = &parsed.root;
    let human = parsed.human;
    let document = match mode {
        "discover" | "inspect" => {
            if let Some(selector) = values.get("--module") {
                serde_json::to_string_pretty(
                    proposal
                        .resolve_module(selector)
                        .map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?
                    + "\n"
            } else if human {
                proposal.to_human()
            } else {
                proposal.to_canonical_json().map_err(|e| e.to_string())?
            }
        }
        "review" => {
            let state = proposal
                .assessment()
                .ok_or("NOT_EVALUABLE: no evaluated target available")?
                .predicted_state()
                .digest()
                .map_err(|e| e.to_string())?;
            let reviewed = review_onboarding_baseline(root, proposal, &state, findings)
                .map_err(|e| e.to_string())?;
            if human {
                reviewed.to_human()
            } else {
                reviewed.to_canonical_json().map_err(|e| e.to_string())?
            }
        }
        "apply" => apply_repository_onboarding(root, proposal)
            .map_err(|e| e.to_string())?
            .to_canonical_json()
            .map_err(|e| e.to_string())?,
        "recover" => {
            let transaction = values
                .get("--transaction")
                .ok_or("INVALID_ARGUMENT: --transaction is required")?;
            let recovery = match values.get("--recovery").copied() {
                Some("resume") => MigrationRecoveryMode::Resume,
                Some("rollback") => MigrationRecoveryMode::Rollback,
                _ => {
                    return Err(
                        "INVALID_ARGUMENT: explicit --recovery resume or rollback is required"
                            .into(),
                    );
                }
            };
            let storage = fortress_core::migration_adapter::default_migration_storage()
                .map_err(|e| e.to_string())?;
            let result = recover_repository_onboarding(
                root,
                proposal,
                transaction,
                recovery,
                None,
                &storage,
                &NoMutationFaults,
            )
            .map_err(|e| e.to_string())?;
            serde_json::to_string_pretty(&serde_json::json!({"outcome":result.outcome,"actual_source_ref":result.actual_source_ref,"transaction_ref":result.transaction_ref,"receipt":result.receipt,"certification":"NOT_ESTABLISHED"})).map_err(|e|e.to_string())?+"\n"
        }
        _ => return Err("INVALID_ARGUMENT: unsupported adoption operation".into()),
    };
    if human && matches!(mode, "apply" | "recover") {
        let value = serde_json::from_str(&document).map_err(|e| e.to_string())?;
        return Ok(fortress_core::query::render_inspection_value(&value));
    }
    Ok(document)
}
fn execute(args: &[String], output: &mut impl Write) -> Result<(), String> {
    let parsed = parse_arguments(args)?;
    let proposal = load_review(&parsed)?;
    let document = render_action(&parsed, &proposal)?;
    publish(
        &parsed.root,
        parsed.values.get("--output"),
        &document,
        output,
    )
}
