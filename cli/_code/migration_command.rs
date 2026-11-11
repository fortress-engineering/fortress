//! Thin explicit migration CLI; repository data never supplies a trusted external grant port.
use fortress_core::development_governance::{
    AuthorizationRule, NoGrantValidator, TrustedBasePolicy, UnmediatedHost,
};
use fortress_core::migration_adapter::{
    CanonicalMigrationAuthority, CanonicalMigrationEvaluator, default_migration_storage,
};
use fortress_core::migration_governance::{
    MigrationError, MigrationEvaluator, MigrationOperation, MigrationOptions, MigrationPlan,
    MigrationReceipt, MigrationRecoveryMode, MigrationServices, NoMutationFaults, apply_migration,
    export_reviewed_migration_plan, preview_migration, recover_migration,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewSelection {
    base_state_ref: String,
    base_authority_ref: String,
    root_policy_ref: String,
    require_assurance: bool,
    rules: Vec<AuthorizationRule>,
}
fn error(code: &str, message: impl Into<String>) -> MigrationError {
    MigrationError {
        code: code.into(),
        message: message.into(),
        transaction_ref: None,
    }
}
fn convert(e: impl std::fmt::Display) -> MigrationError {
    error("INVALID_INPUT", e.to_string())
}
fn read(path: &str) -> Result<String, MigrationError> {
    let root = std::env::current_dir().map_err(convert)?;
    let value = fortress_core::portable_load::load_portable_json(&root, Path::new(path))
        .map_err(convert)?;
    serde_json::to_string(&value).map_err(convert)
}
pub(super) fn run<O: Write, E: Write>(
    args: &[String],
    output: &mut O,
    errors: &mut E,
) -> io::Result<u8> {
    match execute(args, output) {
        Ok(()) => Ok(crate::EXIT_SUCCESS),
        Err(failure) => {
            if args.windows(2).any(|a| a == ["--format", "json"]) {
                writeln!(
                    errors,
                    "{}",
                    serde_json::to_string(&failure).map_err(io::Error::other)?
                )?;
            } else {
                writeln!(errors, "migration failed: {failure}")?;
            }
            Ok(crate::EXIT_USAGE)
        }
    }
}

type Options<'a> = BTreeMap<&'a str, &'a str>;
struct Request<'a> {
    mode: &'a str,
    options: Options<'a>,
    export: bool,
    human: bool,
}
fn parse(args: &[String]) -> Result<Request<'_>, MigrationError> {
    let mode = args.first().ok_or_else(|| {
        error(
            "INVALID_ARGUMENT",
            "migrate requires preview, inspect, apply or recover",
        )
    })?;
    let mut options = BTreeMap::new();
    let mut export = false;
    let mut i = 1;
    while i < args.len() {
        let key = args[i].as_str();
        i += 1;
        if key == "--export" {
            if export {
                return Err(error("INVALID_ARGUMENT", "duplicate --export"));
            }
            export = true;
            continue;
        }
        if ![
            "--root",
            "--operations",
            "--plan",
            "--receipt",
            "--transaction",
            "--direction",
            "--storage-root",
            "--base-selection",
            "--reviewed-intent",
            "--format",
        ]
        .contains(&key)
        {
            return Err(error("INVALID_ARGUMENT", format!("unknown option {key}")));
        }
        let value = args
            .get(i)
            .ok_or_else(|| error("INVALID_ARGUMENT", format!("missing value for {key}")))?;
        i += 1;
        if options.insert(key, value.as_str()).is_some() {
            return Err(error("INVALID_ARGUMENT", format!("duplicate {key}")));
        }
    }
    let human = match options.get("--format").copied().unwrap_or("human") {
        "human" => true,
        "json" => false,
        _ => return Err(error("INVALID_ARGUMENT", "format must be human or json")),
    };
    let mut allowed = vec!["--root", "--format"];
    allowed.extend(match mode.as_str() {
        "preview" => vec!["--operations", "--base-selection", "--reviewed-intent"],
        "inspect" => vec!["--plan", "--receipt"],
        "apply" => vec!["--plan", "--storage-root"],
        "recover" => vec!["--plan", "--transaction", "--direction", "--storage-root"],
        _ => {
            return Err(error(
                "INVALID_ARGUMENT",
                "migrate requires preview, inspect, apply or recover",
            ));
        }
    });
    if options.keys().any(|key| !allowed.contains(key)) || export && mode != "preview" {
        return Err(error(
            "INVALID_ARGUMENT",
            "option does not apply to this migration mode",
        ));
    }
    Ok(Request {
        mode,
        options,
        export,
        human,
    })
}
fn write<O: Write>(output: &mut O, bytes: &[u8]) -> Result<(), MigrationError> {
    output.write_all(bytes).map_err(convert)
}
fn execute<O: Write>(args: &[String], output: &mut O) -> Result<(), MigrationError> {
    let request = parse(args)?;
    let Request {
        mode,
        options,
        export,
        human,
    } = request;
    if mode == "inspect" {
        return inspect(&options, human, output);
    }
    let root = PathBuf::from(options.get("--root").copied().unwrap_or("."))
        .canonicalize()
        .map_err(convert)?;
    if mode == "preview" {
        preview(&root, &options, export, human, output)
    } else {
        apply(&root, mode, &options, human, output)
    }
}
fn inspect<O: Write>(
    options: &Options<'_>,
    human: bool,
    output: &mut O,
) -> Result<(), MigrationError> {
    if let Some(path) = options.get("--receipt") {
        if options.contains_key("--plan") {
            return Err(error(
                "INVALID_ARGUMENT",
                "inspect accepts exactly one plan or receipt",
            ));
        }
        let receipt = MigrationReceipt::from_json_str(&read(path)?)?;
        return write(
            output,
            &if human {
                receipt.to_human().into_bytes()
            } else {
                receipt.to_canonical_bytes()?
            },
        );
    }
    let plan = MigrationPlan::from_json_str(&read(
        options
            .get("--plan")
            .ok_or_else(|| error("INVALID_ARGUMENT", "explicit plan or receipt required"))?,
    )?)?;
    write(
        output,
        &if human {
            plan.to_human().into_bytes()
        } else {
            plan.to_canonical_bytes()?
        },
    )
}
fn preview<O: Write>(
    root: &Path,
    options: &Options<'_>,
    export: bool,
    human: bool,
    output: &mut O,
) -> Result<(), MigrationError> {
    let selected = if let Some(path) = options.get("--base-selection") {
        let s: PreviewSelection =
            fortress_core::wire::parse_public_json(&read(path)?).map_err(convert)?;
        Some(
            TrustedBasePolicy::from_host(
                s.base_state_ref,
                s.base_authority_ref,
                s.root_policy_ref,
                s.require_assurance,
                s.rules,
            )
            .map_err(convert)?,
        )
    } else {
        None
    };
    let evaluator = CanonicalMigrationEvaluator;
    fortress_core::heavy_admission::assert_no_incomplete_migration(root).map_err(convert)?;
    let operations: Vec<MigrationOperation> = fortress_core::wire::parse_public_json(&read(
        options
            .get("--operations")
            .ok_or_else(|| error("INVALID_ARGUMENT", "explicit --operations required"))?,
    )?)
    .map_err(convert)?;
    let authority = CanonicalMigrationAuthority {
        policy: selected.as_ref(),
        host: &UnmediatedHost,
        validator: &NoGrantValidator,
        evaluation_time: None,
        reviewed_initial_intent_ref: options.get("--reviewed-intent").copied(),
        finding_proposal: None,
        identity_plan: None,
    };
    let before = evaluator.observe(root)?;
    let preview = preview_migration(
        &evaluator,
        &authority,
        &before,
        operations,
        MigrationOptions::default(),
    )?;
    if export {
        export_reviewed_migration_plan(root, &preview.plan)?;
    }
    write(
        output,
        &if human {
            preview.plan.to_human().into_bytes()
        } else {
            preview.plan.to_canonical_bytes()?
        },
    )
}
fn apply<O: Write>(
    root: &Path,
    mode: &str,
    options: &Options<'_>,
    human: bool,
    output: &mut O,
) -> Result<(), MigrationError> {
    let evaluator = CanonicalMigrationEvaluator;
    let plan = MigrationPlan::from_json_str(&read(
        options
            .get("--plan")
            .ok_or_else(|| error("INVALID_ARGUMENT", "explicit --plan required"))?,
    )?)?;
    let authority = CanonicalMigrationAuthority {
        policy: None,
        host: &UnmediatedHost,
        validator: &NoGrantValidator,
        evaluation_time: None,
        reviewed_initial_intent_ref: plan.authorization().reviewed_initial_intent_ref.as_deref(),
        finding_proposal: None,
        identity_plan: None,
    };
    let storage = if let Some(path) = options.get("--storage-root") {
        fortress_core::runtime_storage::MigrationStorage::new(
            PathBuf::from(path),
            fortress_core::runtime_storage::StoragePolicy::default(),
        )?
    } else {
        default_migration_storage()?
    };
    let services = MigrationServices {
        evaluator: &evaluator,
        authority: &authority,
        resources: &storage,
        observer: &NoMutationFaults,
    };
    if mode == "apply" {
        let result = apply_migration(root, &plan, &services)?;
        return write(
            output,
            &if human {
                result.receipt.to_human().into_bytes()
            } else {
                result.receipt.to_canonical_bytes()?
            },
        );
    }
    let direction = match options.get("--direction").copied() {
        Some("resume") => MigrationRecoveryMode::Resume,
        Some("rollback") => MigrationRecoveryMode::Rollback,
        _ => {
            return Err(error(
                "INVALID_ARGUMENT",
                "explicit --direction resume or rollback required",
            ));
        }
    };
    let transaction = options
        .get("--transaction")
        .ok_or_else(|| error("INVALID_ARGUMENT", "explicit --transaction required"))?;
    let recovery = recover_migration(root, &plan, transaction, direction, &services)?;
    let value = serde_json::json!({"outcome":recovery.outcome,"actual_source_ref":recovery.actual_source_ref,"receipt":recovery.receipt,"transaction_ref":recovery.transaction_ref});
    if human {
        write(
            output,
            format!(
                "Migration recovery: {}\nActual source: {}\n",
                value["outcome"].as_str().unwrap_or_default(),
                value["actual_source_ref"].as_str().unwrap_or_default()
            )
            .as_bytes(),
        )
    } else {
        write(
            output,
            &fortress_core::wire::canonicalize_public_json(&value.to_string()).map_err(convert)?,
        )
    }
}
