//! Thin explicit read-only candidate evaluation and reconciliation commands.
use fortress_core::candidate::{
    CandidateRequest, CandidateWorkspace, HypotheticalEvaluation, NativeCandidateSelection,
    NativeCandidateSubject, inspect_post_write,
};
use fortress_core::development_governance::{
    AuthorizationRule, NoGrantValidator, TrustedBasePolicy, UnmediatedHost,
};
use fortress_core::go_observation::{GoPackageSelection, observe_go_candidate_sensitivity};
use fortress_core::migration_adapter::CanonicalMigrationAuthority;
use fortress_core::migration_governance::MigrationError;
use fortress_core::portable::digest;
use fortress_core::wire::{JsonAdmissionLimits, admit_json, parse_strict_json_bytes};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

fn error(message: impl Into<String>) -> MigrationError {
    MigrationError {
        code: "INVALID_ARGUMENT".into(),
        message: message.into(),
        transaction_ref: None,
    }
}
fn convert(e: impl std::fmt::Display) -> MigrationError {
    error(e.to_string())
}
fn load(root: &Path, path: &str) -> Result<String, MigrationError> {
    let value =
        fortress_core::portable_load::load_portable_json(root, Path::new(path)).map_err(convert)?;
    serde_json::to_string(&value).map_err(convert)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewSelection {
    base_state_ref: String,
    base_authority_ref: String,
    root_policy_ref: String,
    require_assurance: bool,
    rules: Vec<AuthorizationRule>,
}

const NATIVE_DESCRIPTOR_SCHEMA: &str = "urn:fortress:host:v1:native-candidate-inspection";
const NATIVE_DESCRIPTOR_LIMIT: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeInspectionDescriptor {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    inspection: NativeInspectionHost,
}

#[derive(Deserialize)]
#[serde(tag = "language", rename_all = "lowercase", deny_unknown_fields)]
enum NativeInspectionHost {
    Go {
        registration: PathBuf,
        package: GoPackageDescriptor,
        subject: GoSubjectDescriptor,
    },
    Python {
        registration: PathBuf,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoPackageDescriptor {
    directory: String,
    package_path: String,
    go_version: String,
    target_os: String,
    target_arch: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoSubjectDescriptor {
    source_path: String,
    source_ref: String,
    function: String,
}

struct NativeInspection<'a> {
    path: &'a Path,
    bytes: Vec<u8>,
    host: NativeInspectionHost,
}

impl<'a> NativeInspection<'a> {
    fn load(root: &Path, path: &'a Path) -> Result<Self, MigrationError> {
        let bytes = read_native_descriptor(root, path)?;
        admit_json(
            &bytes,
            JsonAdmissionLimits {
                bytes: NATIVE_DESCRIPTOR_LIMIT,
                depth: 5,
                nodes: 64,
                token_bytes: 4096,
            },
        )
        .map_err(convert)?;
        let descriptor: NativeInspectionDescriptor =
            parse_strict_json_bytes(&bytes).map_err(convert)?;
        if descriptor.schema != NATIVE_DESCRIPTOR_SCHEMA || descriptor.schema_version != 1 {
            return Err(error("unsupported native candidate inspection descriptor"));
        }
        Ok(Self {
            path,
            bytes,
            host: descriptor.inspection,
        })
    }

    fn revalidate(&self, root: &Path) -> Result<(), MigrationError> {
        if read_native_descriptor(root, self.path)? != self.bytes {
            return Err(MigrationError {
                code: "SOURCE_DRIFT".into(),
                message: "native candidate inspection descriptor changed".into(),
                transaction_ref: None,
            });
        }
        Ok(())
    }

    fn attach(
        &self,
        root: &Path,
        workspace: &CandidateWorkspace,
        retained: NativeCandidateSelection<'_>,
        assessment: &HypotheticalEvaluation,
    ) -> Result<serde_json::Value, MigrationError> {
        self.revalidate(root)?;
        let result = match &self.host {
            NativeInspectionHost::Go {
                registration,
                package,
                subject,
            } => {
                let package = GoPackageSelection {
                    directory: if package.directory == "." {
                        ""
                    } else {
                        &package.directory
                    },
                    package_path: &package.package_path,
                    go_version: &package.go_version,
                    target_os: &package.target_os,
                    target_arch: &package.target_arch,
                };
                let subject = NativeCandidateSubject {
                    source_path: &subject.source_path,
                    source_ref: &subject.source_ref,
                    function: &subject.function,
                };
                super::go_body_command::with_registered_body(
                    root,
                    registration,
                    |pin, collector| {
                        Ok(observe_go_candidate_sensitivity(
                            workspace,
                            retained,
                            package,
                            subject,
                            pin,
                            |input| collector.run(input),
                        ))
                    },
                )
                .map_err(convert)?
            }
            NativeInspectionHost::Python { registration } => {
                super::python_scalar_command::inspect_candidate(
                    root,
                    registration,
                    workspace,
                    retained,
                )
            }
        };
        self.revalidate(root)?;
        let native_inspection = result?;
        Ok(json!({
            "$schema": "urn:fortress:derived:v1:overlay-native-candidate-inspection",
            "schema_version": 1,
            "status": "PROPOSED",
            "actual_state": false,
            "descriptor_ref": digest(&self.bytes),
            "assessment": assessment,
            "native_inspection": native_inspection,
        }))
    }
}

fn read_native_descriptor(root: &Path, path: &Path) -> Result<Vec<u8>, MigrationError> {
    super::verifier_process::require_external_asset(path, root).map_err(convert)?;
    super::provider_command::read_bounded(path, NATIVE_DESCRIPTOR_LIMIT).map_err(convert)
}

pub(super) fn run<O: Write, E: Write>(
    args: &[String],
    output: &mut O,
    errors: &mut E,
) -> io::Result<u8> {
    match execute(args, output) {
        Ok(()) => Ok(crate::EXIT_SUCCESS),
        Err(failure) => {
            writeln!(
                errors,
                "{}",
                serde_json::to_string(&failure).map_err(io::Error::other)?
            )?;
            Ok(crate::EXIT_USAGE)
        }
    }
}
struct OverlayRequest<'a> {
    mode: &'a str,
    options: BTreeMap<&'a str, &'a str>,
    export: bool,
    human: bool,
    original_states: Vec<&'a str>,
}
fn parse(args: &[String]) -> Result<OverlayRequest<'_>, MigrationError> {
    let mode = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| error("overlay requires base, evaluate, inspect or reconcile"))?;
    if !["base", "evaluate", "inspect", "reconcile"].contains(&mode) {
        return Err(error("unknown overlay mode; no apply/write method exists"));
    }
    let mut options = BTreeMap::new();
    let mut original_states = Vec::new();
    let mut export = false;
    let mut index = 1;
    while index < args.len() {
        let key = args[index].as_str();
        index += 1;
        if key == "--export" && mode == "evaluate" && !export {
            export = true;
            continue;
        }
        if ![
            "--root",
            "--request",
            "--proposal",
            "--base-selection",
            "--storage-root",
            "--client",
            "--candidate",
            "--format",
            "--original-state",
            "--native-inspection",
        ]
        .contains(&key)
        {
            return Err(error(format!("unknown overlay option {key}")));
        }
        let value = args
            .get(index)
            .ok_or_else(|| error(format!("{key} requires a value")))?;
        index += 1;
        if key == "--original-state" {
            if mode != "evaluate" || original_states.len() >= 16 {
                return Err(error(
                    "original state preload requires evaluate and at most sixteen references",
                ));
            }
            original_states.push(value.as_str());
            continue;
        }
        if options.insert(key, value.as_str()).is_some() {
            return Err(error(format!("duplicate {key}")));
        }
    }
    let mut allowed = vec!["--root", "--format"];
    allowed.extend(match mode {
        "evaluate" => vec![
            "--request",
            "--base-selection",
            "--storage-root",
            "--client",
            "--candidate",
            "--native-inspection",
        ],
        "inspect" | "reconcile" => vec!["--proposal"],
        _ => vec![],
    });
    if options.keys().any(|k| !allowed.contains(k)) {
        return Err(error("option does not apply to this overlay mode"));
    }
    if export && options.contains_key("--native-inspection") {
        return Err(error("native candidate inspection cannot be exported"));
    }
    let human = match options.get("--format").copied().unwrap_or("human") {
        "human" => true,
        "json" => false,
        _ => return Err(error("format must be human or json")),
    };
    Ok(OverlayRequest {
        mode,
        options,
        export,
        human,
        original_states,
    })
}
fn execute<O: Write>(args: &[String], output: &mut O) -> Result<(), MigrationError> {
    let OverlayRequest {
        mode,
        options,
        export,
        human,
        original_states,
    } = parse(args)?;
    let root = Path::new(options.get("--root").copied().unwrap_or("."))
        .canonicalize()
        .map_err(convert)?;
    let native = options
        .get("--native-inspection")
        .map(|path| NativeInspection::load(&root, Path::new(path)))
        .transpose()?;
    let value = if matches!(mode, "inspect" | "reconcile") {
        let path = options
            .get("--proposal")
            .ok_or_else(|| error("explicit --proposal required"))?;
        let candidate = HypotheticalEvaluation::from_json_str(&load(&root, path)?)?;
        if mode == "reconcile" {
            serde_json::to_value(inspect_post_write(
                &root,
                &candidate,
                &AtomicBool::new(false),
            )?)
            .map_err(convert)?
        } else {
            serde_json::to_value(candidate).map_err(convert)?
        }
    } else {
        let mut workspace = if let Some(storage) = options.get("--storage-root") {
            CandidateWorkspace::open(
                &root,
                Path::new(storage),
                fortress_core::session::SessionOptions::default(),
            )?
        } else {
            CandidateWorkspace::open_cold(&root)?
        };
        if !original_states.is_empty() {
            let states = original_states
                .iter()
                .map(|reference| {
                    fortress_core::transition_load::load_comparison_state(&root, reference)
                        .map_err(convert)
                })
                .collect::<Result<Vec<_>, _>>()?;
            workspace = workspace.with_original_states(states)?;
        }
        if mode == "base" {
            json!({"base_source_ref":workspace.base_source_ref(),"context_ref":workspace.context_ref(),"base_state_ref":workspace.base_state().digest().map_err(convert)?,"trusted_base_authority":workspace.base_state().governing_identity().map_err(convert)?,"request_schema":"urn:fortress:derived:v1:candidate-request","request_schema_version":1,"status":"OBSERVED_BASE","permission":"NONE","actual_certification":false})
        } else {
            evaluate_proposal(&root, &mut workspace, &options, export, native)?
        }
    };
    if human {
        write!(
            output,
            "{}",
            fortress_core::query::render_inspection_value(&value)
        )
        .map_err(convert)?;
    } else {
        output
            .write_all(
                &fortress_core::wire::canonicalize_public_json(&value.to_string())
                    .map_err(convert)?,
            )
            .map_err(convert)?;
        writeln!(output).map_err(convert)?;
    }
    Ok(())
}

fn evaluate_proposal(
    root: &Path,
    workspace: &mut CandidateWorkspace,
    options: &BTreeMap<&str, &str>,
    export: bool,
    native: Option<NativeInspection<'_>>,
) -> Result<serde_json::Value, MigrationError> {
    let path = options
        .get("--request")
        .ok_or_else(|| error("explicit --request required"))?;
    let request: CandidateRequest =
        fortress_core::wire::parse_public_json(&load(root, path)?).map_err(convert)?;
    let selected = if let Some(path) = options.get("--base-selection") {
        let s: PreviewSelection =
            fortress_core::wire::parse_public_json(&load(root, path)?).map_err(convert)?;
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
    let authority = CanonicalMigrationAuthority {
        policy: selected.as_ref(),
        host: &UnmediatedHost,
        validator: &NoGrantValidator,
        evaluation_time: None,
        reviewed_initial_intent_ref: None,
        finding_proposal: None,
        identity_plan: None,
    };
    let cancelled = AtomicBool::new(false);
    let retained = NativeCandidateSelection {
        client: options.get("--client").copied().unwrap_or("cli"),
        candidate: options.get("--candidate").copied().unwrap_or("proposal"),
        cancelled: &cancelled,
    };
    let candidate = workspace.evaluate(
        retained.client,
        retained.candidate,
        request,
        &authority,
        retained.cancelled,
    )?;
    if let Some(native) = native {
        return native.attach(root, workspace, retained, &candidate);
    }
    let exported = if export {
        Some(candidate.export_proposal(root)?)
    } else {
        None
    };
    if let Some(path) = exported {
        Ok(json!({"proposal_path":path,"assessment":candidate}))
    } else {
        serde_json::to_value(candidate).map_err(convert)
    }
}
