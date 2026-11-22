//! Read-only upgrade discovery and exact preview.

use fortress_core::development_governance::{NoGrantValidator, UnmediatedHost};
use fortress_core::migration_adapter::CanonicalMigrationAuthority;
use fortress_core::migration_governance::MigrationError;
use fortress_core::migration_governance::upgrade::{UpgradeAdapter, compatibility};
use fortress_core::upgrade_load::{
    UpgradeOperations, inspect_upgrade_base, preview_repository_upgrade,
};
use fortress_core::wire::{parse_public_json, readable_text};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;

pub(super) fn run(
    args: &[String],
    output: &mut impl Write,
    errors: &mut impl Write,
) -> io::Result<u8> {
    let json = args.windows(2).any(|pair| pair == ["--format", "json"]);
    match execute(args, output, json) {
        Ok(()) => Ok(crate::EXIT_SUCCESS),
        Err(error) => {
            if json {
                writeln!(
                    errors,
                    "{}",
                    serde_json::to_string(&error).map_err(io::Error::other)?
                )?;
            } else {
                writeln!(
                    errors,
                    "upgrade failed: {}",
                    readable_text(&error.to_string())
                )?;
            }
            Ok(crate::EXIT_USAGE)
        }
    }
}

fn execute(args: &[String], output: &mut impl Write, json: bool) -> Result<(), MigrationError> {
    let [mode, params @ ..] = args else {
        return Err(invalid(
            "upgrade requires inspect, compatibility or preview",
        ));
    };
    let allowed: &[&str] = match mode.as_str() {
        "inspect" => &["--root", "--format"],
        "compatibility" => &["--from", "--to", "--format"],
        "preview" => &[
            "--root",
            "--format",
            "--editions",
            "--operations",
            "--transform",
            "--base-selection",
        ],
        _ => {
            return Err(invalid(
                "upgrade requires inspect, compatibility or preview",
            ));
        }
    };
    let mut options = BTreeMap::new();
    let chunks = params.chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err(invalid("an upgrade option is missing its value"));
    }
    for pair in chunks {
        if !allowed.contains(&pair[0].as_str())
            || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err(invalid("unknown or duplicate upgrade option"));
        }
    }
    if !matches!(options.get("--format"), None | Some(&"human" | &"json")) {
        return Err(invalid("format must be human or json"));
    }
    let required = |name: &str| {
        options
            .get(name)
            .copied()
            .ok_or_else(|| invalid(format!("{name} is required")))
    };
    let root = Path::new(options.get("--root").copied().unwrap_or("."));
    match mode.as_str() {
        "inspect" => {
            let pin = inspect_upgrade_base(root)?;
            if json {
                serde_json::to_writer(&mut *output, &pin).map_err(invalid)?;
                writeln!(output).map_err(invalid)?;
            } else {
                writeln!(
                    output,
                    "{} {} {}",
                    readable_text(&pin.edition.standard_id),
                    readable_text(&pin.edition.edition),
                    pin.edition.release_digest
                )
                .map_err(invalid)?;
                writeln!(
                    output,
                    "State {} · Authority {}",
                    pin.state_ref, pin.authority_ref
                )
                .map_err(invalid)?;
            }
        }
        "compatibility" => {
            let result = compatibility(required("--from")?, required("--to")?)?;
            if json {
                serde_json::to_writer(&mut *output, &result).map_err(invalid)?;
                writeln!(output).map_err(invalid)?;
            } else {
                let status = serde_json::to_value(result.status).map_err(invalid)?;
                writeln!(output, "{}", status.as_str().unwrap_or("INVALID")).map_err(invalid)?;
                if let Some(transform) = result.transform {
                    writeln!(output, "Transform {transform}").map_err(invalid)?;
                }
            }
        }
        _ => preview(root, &options, required("--editions")?, output, json)?,
    }
    Ok(())
}

fn preview(
    root: &Path,
    options: &BTreeMap<&str, &str>,
    editions: &str,
    output: &mut impl Write,
    json: bool,
) -> Result<(), MigrationError> {
    let adapter: UpgradeAdapter =
        parse_public_json(&super::migration_command::read(editions)?).map_err(invalid)?;
    let policy = options
        .get("--base-selection")
        .map(|path| super::migration_command::preview_selection(path))
        .transpose()?;
    let identity_plan = match options.get("--transform").copied() {
        None => None,
        Some("identity") if !options.contains_key("--operations") => Some(
            fortress_core::identity_migration::plan_repository_identity_migration(root)
                .map_err(invalid)?,
        ),
        _ => {
            return Err(invalid(
                "use --transform identity without explicit operations",
            ));
        }
    };
    let authority = CanonicalMigrationAuthority {
        policy: policy.as_ref(),
        host: &UnmediatedHost,
        validator: &NoGrantValidator,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: identity_plan.as_ref(),
    };
    let operations = match (options.get("--operations"), identity_plan.as_ref()) {
        (Some(path), _) => UpgradeOperations::Explicit(
            parse_public_json(&super::migration_command::read(path)?).map_err(invalid)?,
        ),
        (None, Some(identity)) => UpgradeOperations::Identity(identity),
        (None, None) => UpgradeOperations::NativeConfiguration,
    };
    let result = preview_repository_upgrade(root, &adapter, operations, &authority)?;
    if json {
        output
            .write_all(&result.to_canonical_bytes()?)
            .map_err(invalid)?;
        writeln!(output).map_err(invalid)?;
    } else {
        writeln!(output, "PROPOSED {}", result.digest).map_err(invalid)?;
        writeln!(
            output,
            "{} to {}",
            readable_text(&result.original.pin.edition),
            readable_text(&result.target.pin.edition)
        )
        .map_err(invalid)?;
        for axis in &result.transition.input_deltas {
            writeln!(
                output,
                "{:?} {:?} (complete inventory: {})",
                axis.axis, axis.change, axis.complete
            )
            .map_err(invalid)?;
        }
        for change in &result.rules {
            writeln!(
                output,
                "{} {} (rule logic changed: {})",
                change.change,
                readable_text(&change.id),
                change.logic_changed
            )
            .map_err(invalid)?;
        }
        if let Some(admission) = &result.admission {
            writeln!(
                output,
                "{} findings in the separate proposed admission assessment",
                admission.findings.len()
            )
            .map_err(invalid)?;
        }
        if let Some(plan) = &result.plan {
            writeln!(output, "Review exact migration plan {}", plan.digest()).map_err(invalid)?;
        }
        for limitation in &result.limitations {
            writeln!(output, "{limitation}").map_err(invalid)?;
        }
    }
    Ok(())
}

fn invalid(error: impl std::fmt::Display) -> MigrationError {
    MigrationError {
        code: "INVALID_UPGRADE_INPUT".into(),
        message: error.to_string(),
        transaction_ref: None,
    }
}
