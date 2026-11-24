//! Independently bound scoped native filesystem operation controls.

use fortress_core::program_semantics::ContextKnowledge;
use fortress_core::semantic_analysis::FunctionEffect;
use fortress_core::state_effect_analysis::{
    HypotheticalPythonFilesystemCall, NativeFilesystemBatch, NativeFilesystemBinding,
    NativeFilesystemCall, NativeFilesystemCallee, NativeFilesystemDisposition,
    NativeFilesystemError, NativeFilesystemLanguage, NativeFilesystemOperation, SummaryContext,
    SummaryEffectBound, project_hypothetical_python_filesystem, project_native_filesystem_effects,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const RECORD: &[u8] = include_bytes!("../_data/native_filesystem_reference_v1.json");
const IDENTITY: &str = "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const OTHER: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Deserialize)]
struct CatalogWitness {
    language: String,
    target: String,
    version: String,
    source_context: String,
    type_bindings: Vec<String>,
    features: Vec<String>,
    summary_id: String,
    operation_ref: String,
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R08-006`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R08
#[test]
fn hypothetical_python_operation_keeps_original_and_conditional_facts_separate() {
    let source = b"from pathlib import Path\ndef selected():\n    return Path('sentinel.bin').write_bytes(b'A')\n";
    let (_, contexts) = fixture();
    let binding = NativeFilesystemBinding {
        snapshot_fingerprint: IDENTITY,
        source_view_sha256: "sha256:d9d444a8298ef914a9f791df8f13471e21f324dc5bd79f7bcb1336d9a3ef9a3e",
        authority_sha256: IDENTITY,
        evaluation_sha256: IDENTITY,
        source_path: "src/subject.py",
        source_sha256: "sha256:e6c8593171dcb9da921934c6b50c363901b6400caaa4b0d159c2271919b62add",
    };
    for known in contexts
        .iter()
        .filter(|context| context.language == "python")
    {
        let context = matches_context(known);
        let proposal = HypotheticalPythonFilesystemCall {
            binding,
            source_observation_sha256: IDENTITY,
            source_scope_sha256: "sha256:33d25733a4dba571be8ba20d0c1066fe3c69a3f3f3305c9e9aa762b974286b13",
            installed_origin_sha256: IDENTITY,
            startup_assumptions_sha256: IDENTITY,
            declaration_sha256: &known.operation_ref,
            summary_context: &context,
            site: [52, 90],
        };
        assert_eq!(&source[52..90], b"Path('sentinel.bin').write_bytes(b'A')");
        let projected = project_hypothetical_python_filesystem(binding, source, &proposal).unwrap();
        let wire = serde_json::to_value(projected).unwrap();
        assert_eq!(wire["scope"], "HYPOTHETICAL_CLOSED_REFERENCE_ONLY");
        assert_eq!(wire["actual_project_binding"], "UNESTABLISHED");
        assert_eq!(wire["filesystem_result"], "UNESTABLISHED");
        assert_eq!(wire["authorization"], "NOT_ESTABLISHED");
        assert_eq!(wire["execution"], "NOT_RUN_BY_ANALYSIS");
        assert_eq!(wire["upper_bound"]["state"], "UNKNOWN");
        assert_eq!(wire["catalog_disposition"]["status"], "modeled_operation");
        assert_eq!(wire["catalog_disposition"]["summary_id"], known.summary_id);
        assert_eq!(
            wire["catalog_disposition"]["effects"],
            serde_json::json!(["filesystem.write"]),
        );
        assert!(matches!(
            project_hypothetical_python_filesystem(binding, b"changed", &proposal),
            Err(NativeFilesystemError::SourceMismatch)
        ));
        let unbound = HypotheticalPythonFilesystemCall {
            startup_assumptions_sha256: "",
            ..proposal
        };
        assert!(matches!(
            project_hypothetical_python_filesystem(binding, source, &unbound),
            Err(NativeFilesystemError::InvalidObservation)
        ));
        let missing_receiver = SummaryContext {
            type_bindings: ContextKnowledge::Unknown,
            ..context.clone()
        };
        let unbound = HypotheticalPythonFilesystemCall {
            summary_context: &missing_receiver,
            ..proposal
        };
        let projection = project_hypothetical_python_filesystem(binding, source, &unbound).unwrap();
        let wire = serde_json::to_value(projection).unwrap();
        assert_eq!(wire["catalog_disposition"]["status"], "context_unavailable");
        assert!(wire["catalog_disposition"].get("effects").is_none());
    }
}

fn fixture() -> (Value, Vec<CatalogWitness>) {
    let plan: Value = serde_json::from_slice(RECORD).unwrap();
    let contexts = serde_json::from_value(plan["contexts"].clone()).unwrap();
    (plan, contexts)
}

fn binding(entry: &Value) -> NativeFilesystemBinding<'_> {
    NativeFilesystemBinding {
        snapshot_fingerprint: IDENTITY,
        source_view_sha256: IDENTITY,
        authority_sha256: IDENTITY,
        evaluation_sha256: IDENTITY,
        source_path: entry["path"].as_str().unwrap(),
        source_sha256: entry["source_ref"].as_str().unwrap(),
    }
}

fn mode(language: &str) -> (NativeFilesystemLanguage, NativeFilesystemOperation) {
    match language {
        "go" => (
            NativeFilesystemLanguage::Go,
            NativeFilesystemOperation::GoOsWriteFile,
        ),
        "python" => (
            NativeFilesystemLanguage::Python,
            NativeFilesystemOperation::PythonPathWriteBytes,
        ),
        _ => panic!("unexpected fixture language"),
    }
}

fn matches_context(known: &CatalogWitness) -> SummaryContext {
    SummaryContext {
        source_digest: ContextKnowledge::Known(known.source_context.clone()),
        version: ContextKnowledge::Known(known.version.clone()),
        target: ContextKnowledge::Known(known.target.clone()),
        features: ContextKnowledge::Known(known.features.clone()),
        type_bindings: ContextKnowledge::Known(known.type_bindings.clone()),
    }
}

fn call<'a>(row: &Value, callee: NativeFilesystemCallee<'a>) -> NativeFilesystemCall<'a> {
    let [start_byte, end_byte] =
        serde_json::from_value::<[usize; 2]>(row["range"].clone()).unwrap();
    NativeFilesystemCall {
        start_byte,
        end_byte,
        callee,
    }
}

fn invoke<'a>(
    known: &'a CatalogWitness,
    input: &'a Value,
    calls: &'a [NativeFilesystemCall<'a>],
) -> NativeFilesystemBatch<'a> {
    let (language, _) = mode(&known.language);
    NativeFilesystemBatch {
        language,
        binding: binding(input),
        observation_sha256: &known.operation_ref,
        calls,
    }
}

fn native<'a>(
    known: &'a CatalogWitness,
    summary_context: &'a SummaryContext,
) -> NativeFilesystemCallee<'a> {
    NativeFilesystemCallee::ResolvedStandardLibrary {
        operation: mode(&known.language).1,
        declaration_sha256: &known.operation_ref,
        summary_context,
    }
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R08-001`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R08
#[test]
fn one_reviewed_write_per_context_and_no_name_only_effect() {
    let (frozen, contexts) = fixture();
    assert_eq!(contexts.len(), 4);
    for known in &contexts {
        let input = &frozen["fixtures"][&known.language];
        let sites = &input["sites"];
        let source = input["source"].as_str().unwrap().as_bytes();
        let context = matches_context(known);
        let calls = [
            call(&sites[0], native(known, &context)),
            call(&sites[1], NativeFilesystemCallee::LocalOrShadowed),
            call(&sites[2], NativeFilesystemCallee::Unresolved),
        ];
        assert_eq!(
            &source[calls[0].start_byte..calls[0].end_byte],
            &source[calls[1].start_byte..calls[1].end_byte],
            "frozen positive and shadowed sites use identical spelling",
        );
        let batch = invoke(known, input, &calls);
        let resulting = project_native_filesystem_effects(binding(input), source, &batch).unwrap();
        let [positive, shadowed, dynamic] = resulting.sites() else {
            panic!("three scoped facts")
        };
        assert!(
            matches!(positive.disposition(), NativeFilesystemDisposition::ModeledOperation {
            summary_id, effects, ..
        } if summary_id == &known.summary_id && effects == &[FunctionEffect::FilesystemWrite])
        );
        assert_eq!(
            shadowed.disposition(),
            &NativeFilesystemDisposition::LocalOrShadowed
        );
        assert_eq!(
            dynamic.disposition(),
            &NativeFilesystemDisposition::Unresolved
        );
        assert_eq!(resulting.upper_bound(), &SummaryEffectBound::Unknown);
        assert_eq!(resulting.binding(), binding(input));
        let reverse = [calls[2], calls[1], calls[0]];
        let reversed = invoke(known, input, &reverse);
        assert_eq!(
            serde_json::to_vec(&resulting).unwrap(),
            serde_json::to_vec(
                &project_native_filesystem_effects(binding(input), source, &reversed).unwrap()
            )
            .unwrap()
        );
    }
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R08-002`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R08
#[test]
fn exact_declaration_without_exact_context_does_not_select_any_effect() {
    let (frozen, contexts) = fixture();
    for known in &contexts {
        let input = &frozen["fixtures"][&known.language];
        let source = input["source"].as_str().unwrap().as_bytes();
        let stable = matches_context(known);
        for (mismatch, expected) in [
            (
                SummaryContext {
                    features: ContextKnowledge::Unknown,
                    ..stable.clone()
                },
                "summary_features_unknown",
            ),
            (
                SummaryContext {
                    type_bindings: ContextKnowledge::Unknown,
                    ..stable.clone()
                },
                "summary_type_bindings_unknown",
            ),
            (
                SummaryContext {
                    source_digest: ContextKnowledge::Known(OTHER.into()),
                    ..stable.clone()
                },
                "summary_source_digest_mismatch",
            ),
            (
                SummaryContext {
                    target: ContextKnowledge::Known("unknown/native".into()),
                    ..stable
                },
                "summary_target_mismatch",
            ),
        ] {
            let calls = [call(&input["sites"][0], native(known, &mismatch))];
            let batch = invoke(known, input, &calls);
            let projected =
                project_native_filesystem_effects(binding(input), source, &batch).unwrap();
            assert!(matches!(
                projected.sites()[0].disposition(),
                NativeFilesystemDisposition::ContextUnavailable { reasons, .. }
                if reasons.iter().any(|reason| reason == expected)
            ));
            assert_eq!(projected.upper_bound(), &SummaryEffectBound::Unknown);
        }
    }
}

/// `T-AF-STATE-EFFECT-ANALYSIS-0001-R08-003`
/// Fortress requirement: AF-STATE-EFFECT-ANALYSIS-0001-R08
#[test]
fn native_effects_have_no_stale_or_malformed_positive_paths() {
    let (frozen, contexts) = fixture();
    let known = &contexts[0];
    let input = &frozen["fixtures"][&known.language];
    let source = input["source"].as_str().unwrap().as_bytes();
    let context = matches_context(known);
    let calls = [call(&input["sites"][0], native(known, &context))];
    let batch = invoke(known, input, &calls);
    let wrong = NativeFilesystemBinding {
        authority_sha256: OTHER,
        ..binding(input)
    };
    assert!(matches!(
        project_native_filesystem_effects(wrong, source, &batch),
        Err(NativeFilesystemError::BindingMismatch)
    ));
    assert!(matches!(
        project_native_filesystem_effects(binding(input), b"stale", &batch),
        Err(NativeFilesystemError::SourceMismatch)
    ));
    let wrong = NativeFilesystemBinding {
        source_path: "../fixture.go",
        ..binding(input)
    };
    let mut batch = invoke(known, input, &calls);
    batch.binding = wrong;
    assert!(matches!(
        project_native_filesystem_effects(wrong, source, &batch),
        Err(NativeFilesystemError::InvalidObservation)
    ));
    let invalid = [NativeFilesystemCall {
        end_byte: usize::MAX,
        ..calls[0]
    }];
    let batch = invoke(known, input, &invalid);
    assert!(matches!(
        project_native_filesystem_effects(binding(input), source, &batch),
        Err(NativeFilesystemError::InvalidObservation)
    ));
    let duplicates = [calls[0]; 2];
    let batch = invoke(known, input, &duplicates);
    assert!(matches!(
        project_native_filesystem_effects(binding(input), source, &batch),
        Err(NativeFilesystemError::InvalidObservation)
    ));
    let extra = [calls[0]; 65];
    let batch = invoke(known, input, &extra);
    assert!(matches!(
        project_native_filesystem_effects(binding(input), source, &batch),
        Err(NativeFilesystemError::ResourceLimit)
    ));
    assert_eq!(
        format!(
            "sha256:{:x}",
            Sha256::digest(fortress_core::standard::installed_operation_summaries().as_bytes())
        ),
        "sha256:8514ed89dc16d4be9df0b16848cea83926ec498dacf990baf8d49e492001b8bf",
    );
}
