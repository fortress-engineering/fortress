//! Conformance evidence for snapshot-bound Rust implementation observation.

use std::collections::{BTreeMap, BTreeSet};

use fortress_core::implementation_observation::{
    ImplementationObservationError, ImplementationObservationInput, ModuleTerritory,
    ResolutionStatus, SnapshotBoundFile, SourceOwnershipAuthority, TargetClassification,
    observe_rust_implementation, resolve_source_ownership_with_logical_modules,
};
use fortress_core::project::ProjectConfiguration;
use sha2::{Digest, Sha256};

fn snapshot_input(
    files: impl IntoIterator<Item = (&'static str, &'static str)>,
    modules: impl IntoIterator<Item = (&'static str, &'static str)>,
) -> ImplementationObservationInput {
    ImplementationObservationInput::new(
        "sha256:fixture",
        files
            .into_iter()
            .map(|(path, source)| SnapshotBoundFile::from_bytes(path, source.as_bytes()))
            .collect(),
        modules
            .into_iter()
            .map(|(id, path)| ModuleTerritory::new(id, path))
            .collect(),
    )
}

fn logical_project() -> ProjectConfiguration {
    ProjectConfiguration::from_json_str(
        r#"{
  "$schema": "urn:fortress:schema:v3:project-configuration",
  "schema_version": 3,
  "observation_exclusions": [
    ".git"
  ],
  "logical_modules": [
    {
      "module": "AF-BILLING-0001",
      "contract": "_data/logical_modules/billing/contract.json",
      "parent": "PF-FIXTURE",
      "bindings": [
        {
          "kind": "directory",
          "path": "crates/core/src/billing"
        }
      ]
    },
    {
      "module": "AF-PAYMENTS-0001",
      "contract": "_data/logical_modules/payments/contract.json",
      "parent": "PF-FIXTURE",
      "bindings": [
        {
          "kind": "directory",
          "path": "crates/api/src/payments"
        },
        {
          "kind": "file",
          "path": "crates/core/src/ledger/payment.rs"
        }
      ]
    }
  ]
}"#,
    )
    .expect("logical project validates")
}

/// `T-LOGICAL-OWNERSHIP-EXACT-001`
/// Fortress classification: infrastructure
#[test]
fn logical_file_directory_and_partial_ownership_are_distinct() {
    let project = logical_project();
    let paths = [
        "Cargo.toml",
        "crates/api/Cargo.toml",
        "crates/api/src/lib.rs",
        "crates/api/src/payments/charge.rs",
        "crates/core/Cargo.toml",
        "crates/core/src/billing/invoice.rs",
        "crates/core/src/ledger/payment.rs",
        "crates/core/src/unmapped.rs",
    ];
    let known = BTreeSet::from([
        "AF-BILLING-0001".to_owned(),
        "AF-PAYMENTS-0001".to_owned(),
        "PF-FIXTURE".to_owned(),
    ]);
    let result = resolve_source_ownership_with_logical_modules(
        paths,
        &[],
        project.logical_modules(),
        &known,
    );
    let owners = result
        .ownerships()
        .iter()
        .map(|ownership| {
            (
                ownership.source_path(),
                (ownership.owner(), ownership.authority()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        owners["crates/api/src/payments/charge.rs"].0,
        "AF-PAYMENTS-0001"
    );
    assert_eq!(
        owners["crates/core/src/billing/invoice.rs"].0,
        "AF-BILLING-0001"
    );
    assert_eq!(
        owners["crates/core/src/ledger/payment.rs"].0,
        "AF-PAYMENTS-0001"
    );
    assert_eq!(
        owners["crates/core/src/unmapped.rs"].1,
        SourceOwnershipAuthority::CargoAnalysisTerritory
    );
    assert!(result.diagnostics().is_empty());
}

/// `T-LOGICAL-OWNERSHIP-RELOCATION-001`
/// Fortress classification: infrastructure
#[test]
fn changing_only_binding_placement_preserves_semantic_owner() {
    let first = logical_project();
    let moved_source = serde_json::to_string(&serde_json::json!({
        "$schema": "urn:fortress:schema:v3:project-configuration",
        "schema_version": 3,
        "observation_exclusions": [".git"],
        "logical_modules": [{
            "module": "AF-PAYMENTS-0001",
            "contract": "_data/logical_modules/payments/contract.json",
            "parent": "PF-FIXTURE",
            "bindings": [{"kind": "directory", "path": "src/domain/payments"}]
        }]
    }))
    .expect("JSON serializes");
    let moved =
        ProjectConfiguration::from_json_str(&moved_source).expect("moved binding validates");
    let known = BTreeSet::from(["AF-PAYMENTS-0001".to_owned()]);
    let old = resolve_source_ownership_with_logical_modules(
        ["Cargo.toml", "crates/api/src/payments/charge.rs"],
        &[],
        &first.logical_modules()[1..],
        &known,
    );
    let new = resolve_source_ownership_with_logical_modules(
        ["Cargo.toml", "src/domain/payments/charge.rs"],
        &[],
        moved.logical_modules(),
        &known,
    );
    assert_eq!(old.ownerships()[0].owner(), "AF-PAYMENTS-0001");
    assert_eq!(new.ownerships()[0].owner(), "AF-PAYMENTS-0001");
}

/// `T-LOGICAL-OWNERSHIP-SCALE-001`
/// Fortress classification: infrastructure
#[test]
fn ten_thousand_paths_resolve_deterministically() {
    let project = logical_project();
    let mut paths = vec!["Cargo.toml".to_owned(), "crates/api/Cargo.toml".to_owned()];
    paths.extend((0..10_000).map(|index| format!("crates/api/src/payments/item_{index:05}.rs")));
    let known = BTreeSet::from(["AF-BILLING-0001".to_owned(), "AF-PAYMENTS-0001".to_owned()]);
    let first = resolve_source_ownership_with_logical_modules(
        paths.iter().map(String::as_str),
        &[],
        project.logical_modules(),
        &known,
    );
    let second = resolve_source_ownership_with_logical_modules(
        paths.iter().rev().map(String::as_str),
        &[],
        project.logical_modules(),
        &known,
    );
    assert_eq!(first, second);
    assert_eq!(first.ownerships().len(), 10_000);
}

fn basic_cross_package_input() -> ImplementationObservationInput {
    snapshot_input(
        [
            (
                "provider/_data/Cargo.toml",
                "[package]\nname = \"provider\"\nversion = \"0.1.0\"\n[lib]\npath = \"../_code/lib.rs\"\n",
            ),
            (
                "provider/_code/lib.rs",
                "pub struct Value;\npub fn value() -> Value { Value }\n",
            ),
            (
                "consumer/_data/Cargo.toml",
                "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n[lib]\npath = \"../_code/lib.rs\"\n[dependencies]\nprovider = { path = \"../../provider/_data\" }\n",
            ),
            (
                "consumer/_code/lib.rs",
                "use provider::Value;\npub fn consume(_: Value) {}\n",
            ),
        ],
        [
            ("PF-FIXTURE", ""),
            ("AF-PROVIDER-0001", "provider"),
            ("AF-CONSUMER-0001", "consumer"),
        ],
    )
}

/// `T-AF-IMPLEMENTATION-OBSERVATION-0001-R01-001`
/// Fortress requirement: AF-IMPLEMENTATION-OBSERVATION-0001-R01
#[test]
fn repeated_snapshot_analysis_is_byte_fact_deterministic() {
    let input = basic_cross_package_input();
    let first = observe_rust_implementation(&input).expect("fixture observes");
    let second = observe_rust_implementation(&input).expect("fixture repeats");
    assert_eq!(first, second);
    assert_eq!(first.snapshot_fingerprint(), "sha256:fixture");
    assert_eq!(first.analyzer_version(), "1.1.0");
    assert_eq!(first.module_dependencies().len(), 1);
    let edge = &first.module_dependencies()[0];
    assert_eq!(edge.source_module(), "AF-CONSUMER-0001");
    assert_eq!(edge.target_module(), "AF-PROVIDER-0001");
    assert!(!edge.evidence().is_empty());
}

/// `T-AF-IMPLEMENTATION-OBSERVATION-0001-R01-002`
/// Fortress requirement: AF-IMPLEMENTATION-OBSERVATION-0001-R01
#[test]
fn snapshot_byte_mutation_is_rejected_before_parsing() {
    let original = b"pub fn stable() {}";
    let expected = format!("sha256:{:x}", Sha256::digest(original));
    let input = ImplementationObservationInput::new(
        "sha256:fixture",
        vec![SnapshotBoundFile::new(
            "_code/lib.rs",
            u64::try_from(original.len()).expect("length fits"),
            expected,
            b"pub fn changed() {}".to_vec(),
        )],
        vec![ModuleTerritory::new("PF-FIXTURE", "")],
    );
    assert!(matches!(
        observe_rust_implementation(&input),
        Err(ImplementationObservationError::SnapshotIdentityMismatch(path))
            if path.as_ref() == "_code/lib.rs"
    ));
}

/// `T-AF-IMPLEMENTATION-OBSERVATION-0001-R02-001`
/// Fortress requirement: AF-IMPLEMENTATION-OBSERVATION-0001-R02
#[test]
fn structural_rust_paths_resolve_same_crate_modules_and_external_targets() {
    let input = snapshot_input(
        [
            (
                "engine/_data/Cargo.toml",
                "[package]\nname = \"engine\"\nversion = \"0.1.0\"\n[lib]\npath = \"../_code/lib.rs\"\n[dependencies]\nserde = \"1\"\n",
            ),
            (
                "engine/_code/lib.rs",
                "#[path = \"../alpha/_code/alpha.rs\"]\npub mod alpha;\n#[path = \"../beta/_code/beta.rs\"]\npub mod beta;\n",
            ),
            (
                "engine/alpha/_code/alpha.rs",
                "use crate::beta::Thing;\nuse super::beta::Thing as Other;\nuse serde::Serialize;\nuse crate::mystery::unknown;\n#[path = \"local.rs\"]\nmod local;\npub fn run(_: Thing, _: Other) {}\n",
            ),
            (
                "engine/alpha/_code/local.rs",
                "use self::Local as Alias;\npub struct Local;\npub fn local(_: Alias) {}\n",
            ),
            ("engine/beta/_code/beta.rs", "pub struct Thing;\n"),
        ],
        [
            ("PF-FIXTURE", ""),
            ("AF-ENGINE-0001", "engine"),
            ("AF-ALPHA-0001", "engine/alpha"),
            ("AF-BETA-0001", "engine/beta"),
        ],
    );
    let result = observe_rust_implementation(&input).expect("structural fixture observes");
    let edges: Vec<_> = result
        .module_dependencies()
        .iter()
        .map(|edge| (edge.source_module(), edge.target_module()))
        .collect();
    assert!(edges.contains(&("AF-ENGINE-0001", "AF-ALPHA-0001")));
    assert!(edges.contains(&("AF-ENGINE-0001", "AF-BETA-0001")));
    assert!(edges.contains(&("AF-ALPHA-0001", "AF-BETA-0001")));
    assert!(result.observations().iter().any(|observation| {
        observation.target_classification() == TargetClassification::ExternalDependency
            && observation.external_target() == Some("serde")
    }));
    assert!(result.observations().iter().any(|observation| {
        observation.resolution_status() == ResolutionStatus::Unresolved
            && observation.provenance().reference() == "crate::mystery::unknown"
    }));
}

/// `T-AF-IMPLEMENTATION-OBSERVATION-0001-R02-002`
/// Fortress requirement: AF-IMPLEMENTATION-OBSERVATION-0001-R02
#[test]
fn workspace_facades_testing_ownership_and_edge_evidence_are_preserved() {
    let input = snapshot_input(
        [
            (
                "engine/_data/Cargo.toml",
                "[package]\nname = \"engine\"\nversion = \"0.1.0\"\nautotests = false\n[lib]\npath = \"../_code/lib.rs\"\n[[test]]\nname = \"engine_test\"\npath = \"../testing/_code/engine_test.rs\"\n",
            ),
            (
                "engine/_code/lib.rs",
                "#[path = \"../child/_code/child.rs\"]\npub mod child;\n",
            ),
            ("engine/child/_code/child.rs", "pub struct Surface;\n"),
            (
                "engine/testing/_code/engine_test.rs",
                "use engine::child::Surface;\nfn proof(_: Surface) {}\n",
            ),
            (
                "cli/_data/Cargo.toml",
                "[package]\nname = \"cli\"\nversion = \"0.1.0\"\n[lib]\npath = \"../_code/lib.rs\"\n[dependencies]\nengine = { path = \"../../engine/_data\" }\n",
            ),
            (
                "cli/_code/lib.rs",
                "use engine::child::Surface;\nuse engine::child::Surface as Again;\npub fn run(_: Surface, _: Again) {}\n",
            ),
        ],
        [
            ("PF-FIXTURE", ""),
            ("AF-ENGINE-0001", "engine"),
            ("AF-CHILD-0001", "engine/child"),
            ("TEST-ENGINE-0001", "engine/testing"),
            ("TF-CLI-0001", "cli"),
        ],
    );
    let result = observe_rust_implementation(&input).expect("facade fixture observes");
    let edges: BTreeMap<_, _> = result
        .module_dependencies()
        .iter()
        .map(|edge| {
            (
                (edge.source_module(), edge.target_module()),
                edge.evidence().len(),
            )
        })
        .collect();
    assert!(edges.contains_key(&("TEST-ENGINE-0001", "AF-ENGINE-0001")));
    assert!(!edges.contains_key(&("TEST-ENGINE-0001", "AF-CHILD-0001")));
    assert!(edges.contains_key(&("TF-CLI-0001", "AF-ENGINE-0001")));
    assert!(!edges.contains_key(&("TF-CLI-0001", "AF-CHILD-0001")));
    assert!(edges[&("TF-CLI-0001", "AF-ENGINE-0001")] >= 2);
}

mod native_dependency_controls {
    use super::*;
    use fortress_core::implementation_observation::{
        NativeDependencyAdapterError, NativeDependencyBatch, NativeDependencyContext,
        NativeDependencyEndpoint, NativeDependencyFile, NativeDependencyLanguage,
        NativeDependencyOccurrence, NativeDependencyProjection, NativeDependencySiteTarget,
        NativeDependencyTarget, NativeDependencyUnresolved, NativeEndpointOwnership,
        adapt_native_dependencies, resolve_inventory_ownership_with_logical_modules,
    };

    const SNAPSHOT: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const VIEW: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const AUTHORITY: &str =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    const CONTEXT: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
    const RECEIPT: &str = "sha256:5555555555555555555555555555555555555555555555555555555555555555";

    const GO_APP: &str = "// µ\r\npackage app\nimport \"local.test/shared\"\n";
    const GO_ONE: &str = "package shared\n";
    const GO_TWO: &str = "package shared\nconst N = 7\n";
    const GO_ORPHAN: &str = "package orphan\n";
    const PY_APP: &str = "if ready:\n    import pkg.peer\nimport pkg.namespace\n";
    const PY_PEER: &str = "answer = 7\n";

    const SELECTED: NativeDependencyContext<'static> = NativeDependencyContext {
        snapshot_fingerprint: SNAPSHOT,
        source_view_sha256: VIEW,
        authority_sha256: AUTHORITY,
        context_sha256: CONTEXT,
    };

    fn sha(text: &str) -> String {
        format!("sha256:{:x}", Sha256::digest(text.as_bytes()))
    }

    fn file<'a>(path: &'a str, ref_id: &'a str) -> NativeDependencyFile<'a> {
        NativeDependencyFile {
            path,
            sha256: ref_id,
        }
    }

    fn project(split: bool) -> ImplementationObservationInput {
        let files = [
            ("app/main.go", GO_APP),
            ("shared/one.go", GO_ONE),
            ("shared/two.go", GO_TWO),
            ("orphan/source.go", GO_ORPHAN),
            ("pkg/app.py", PY_APP),
            ("pkg/peer.py", PY_PEER),
        ];
        let mut source_bindings = vec![
            ("AF-APP-0001", vec!["app/main.go", "pkg/app.py"]),
            ("AF-SHARED-0001", vec!["shared/one.go", "pkg/peer.py"]),
        ];
        if split {
            source_bindings.push(("AF-OTHER-0001", vec!["shared/two.go"]));
        } else {
            source_bindings[1].1.push("shared/two.go");
        }
        source_bindings.sort_unstable_by_key(|(id, _)| *id);
        for (_, paths) in &mut source_bindings {
            paths.sort_unstable();
        }
        let declarations = source_bindings.iter().map(|(id, paths)| {
            serde_json::json!({
                "module": id,
                "contract": format!("_data/logical/{id}/contract.json"),
                "parent": "PF-FIXTURE",
                "bindings": paths.iter().map(|path|serde_json::json!({"kind":"file", "path":path}))
                    .collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>();
        let encoded = serde_json::to_string(&serde_json::json!({
            "$schema":"urn:fortress:schema:v3:project-configuration",
            "schema_version":3,
            "observation_exclusions":[],
            "logical_modules":declarations,
        }))
        .unwrap();
        let configuration = ProjectConfiguration::from_json_str(&encoded).unwrap();
        let ids = source_bindings
            .iter()
            .map(|(id, _)| (*id).to_owned())
            .collect();
        let authored = resolve_inventory_ownership_with_logical_modules(
            files.iter().map(|(path, _)| *path),
            &[],
            configuration.logical_modules(),
            &ids,
        );
        assert!(authored.diagnostics().is_empty());
        ImplementationObservationInput::new_with_ownership(
            SNAPSHOT,
            files
                .into_iter()
                .map(|(path, content)| SnapshotBoundFile::from_bytes(path, content))
                .collect(),
            authored.ownerships().to_vec(),
        )
    }

    fn go_site(digest: &str) -> NativeDependencyOccurrence<'_> {
        NativeDependencyOccurrence {
            file: file("app/main.go", digest),
            start_byte: 27,
            end_byte: 44,
            reference: "local.test/shared",
        }
    }

    fn adapt<'a>(
        input: &ImplementationObservationInput,
        language: NativeDependencyLanguage,
        endpoints: &'a [NativeDependencyEndpoint<'a>],
    ) -> Result<NativeDependencyProjection<'a>, NativeDependencyAdapterError> {
        adapt_native_dependencies(
            input,
            SELECTED,
            &NativeDependencyBatch {
                language,
                context: SELECTED,
                observation_sha256: RECEIPT,
                endpoints,
            },
        )
    }

    /// T-AF-IMPLEMENTATION-OBSERVATION-0001-R03-001
    /// Fortress requirement: AF-IMPLEMENTATION-OBSERVATION-0001-R03
    #[test]
    fn native_closed_go_package_normalizes_one_exact_direction() {
        assert_eq!(&GO_APP.as_bytes()[27..44], b"local.test/shared");
        let (app, one, two) = (sha(GO_APP), sha(GO_ONE), sha(GO_TWO));
        let targets = [file("shared/two.go", &two), file("shared/one.go", &one)];
        let reversed = [targets[1], targets[0]];
        let selected = NativeDependencyEndpoint {
            occurrence: go_site(&app),
            target: NativeDependencyTarget::GoClosedPackage(&targets),
        };
        let equivalent = NativeDependencyEndpoint {
            occurrence: go_site(&app),
            target: NativeDependencyTarget::GoClosedPackage(&reversed),
        };
        let input = project(false);
        let requests = [selected, equivalent];
        let result = adapt(&input, NativeDependencyLanguage::Go, &requests).unwrap();
        let single = [equivalent];
        let replay = adapt(&input, NativeDependencyLanguage::Go, &single).unwrap();
        assert_eq!(
            serde_json::to_vec(&result).unwrap(),
            serde_json::to_vec(&replay).unwrap()
        );
        assert_eq!(result.context(), SELECTED);
        assert_eq!(result.sites().len(), 1);
        let [edge] = result.observation().module_dependencies() else {
            panic!("one native source edge expected");
        };
        assert_eq!(
            (edge.source_module(), edge.target_module()),
            ("AF-APP-0001", "AF-SHARED-0001")
        );
        let [evidence] = edge.evidence() else {
            panic!("one exact source occurrence expected")
        };
        assert_eq!(evidence.source_path(), "app/main.go");
        assert_eq!(evidence.reference(), "local.test/shared");
        assert_eq!(
            (evidence.location().line(), evidence.location().column()),
            (3, 9)
        );
        assert_eq!(result.observation().issues().len(), 0);

        let split = project(true);
        let result = adapt(&split, NativeDependencyLanguage::Go, &single).unwrap();
        assert!(result.observation().module_dependencies().is_empty());
        assert_eq!(
            result.observation().observations()[0].resolution_status(),
            ResolutionStatus::Unresolved
        );
        assert!(matches!(
            result.sites()[0].target(),
            NativeDependencySiteTarget::GoClosedPackage {
                ownership: NativeEndpointOwnership::ManyOwned { .. },
                ..
            }
        ));
    }

    /// T-AF-IMPLEMENTATION-OBSERVATION-0001-R03-002
    /// Fortress requirement: AF-IMPLEMENTATION-OBSERVATION-0001-R03
    #[test]
    fn python_static_file_origin_retains_scope_and_unknown_runtime() {
        let input = project(false);
        let app = sha(PY_APP);
        let target = sha(PY_PEER);
        let base = NativeDependencyOccurrence {
            file: file("pkg/app.py", &app),
            start_byte: 21,
            end_byte: 29,
            reference: "pkg.peer",
        };
        assert_eq!(
            &PY_APP.as_bytes()[base.start_byte..base.end_byte],
            b"pkg.peer"
        );
        let selected = NativeDependencyEndpoint {
            occurrence: base,
            target: NativeDependencyTarget::PythonStaticOrigin(file("pkg/peer.py", &target)),
        };
        let unresolved = NativeDependencyEndpoint {
            occurrence: NativeDependencyOccurrence {
                reference: "pkg.namespace",
                start_byte: 37,
                end_byte: 50,
                ..base
            },
            target: NativeDependencyTarget::Unresolved(NativeDependencyUnresolved::NamespaceOnly),
        };
        let sites = [unresolved, selected];
        let report = adapt(&input, NativeDependencyLanguage::Python, &sites).unwrap();
        assert_eq!(report.sites().len(), 2);
        let rendered = serde_json::to_value(&report).unwrap();
        assert_eq!(
            rendered["coverage"],
            "positive_scoped_source_only_runtime_and_absence_unestablished",
        );
        let model = report.observation();
        assert_eq!(model.module_dependencies().len(), 1);
        assert_eq!(model.observations().len(), 2);
        let row = serde_json::to_value(&model.observations()[0]).unwrap();
        assert_eq!(row["language"], "python");
        assert_eq!(row["conditionality"], "unestablished");
        assert!(report.sites().iter().any(|site| matches!(
            site.target(),
            NativeDependencySiteTarget::Unresolved {
                reason: NativeDependencyUnresolved::NamespaceOnly
            }
        )));
        let empty = adapt(&input, NativeDependencyLanguage::Python, &[]).unwrap();
        assert!(empty.sites().is_empty());
        assert_eq!(
            serde_json::to_value(&empty).unwrap()["coverage"],
            rendered["coverage"],
        );
    }

    /// T-AF-IMPLEMENTATION-OBSERVATION-0001-R03-003
    /// Fortress requirement: AF-IMPLEMENTATION-OBSERVATION-0001-R03
    #[test]
    fn native_adapter_refuses_rebinding_and_conflicting_receipts() {
        let input = project(false);
        let (app, target, orphan) = (sha(GO_APP), sha(GO_ONE), sha(GO_ORPHAN));
        let one = [file("shared/one.go", &target)];
        let unowned = [file("orphan/source.go", &orphan)];
        let absent = [file("shared/missing.go", &target)];
        let stale = [file("shared/one.go", VIEW)];
        let duplicate = [one[0], one[0]];
        let make = |files| NativeDependencyEndpoint {
            occurrence: go_site(&app),
            target: NativeDependencyTarget::GoClosedPackage(files),
        };
        for (candidate, risk) in [
            (
                &absent[..],
                NativeDependencyAdapterError::SourceIdentityMismatch,
            ),
            (
                &stale[..],
                NativeDependencyAdapterError::SourceIdentityMismatch,
            ),
            (
                &duplicate[..],
                NativeDependencyAdapterError::InvalidEndpoint,
            ),
            (&[][..], NativeDependencyAdapterError::InvalidEndpoint),
        ] {
            assert_eq!(
                adapt(&input, NativeDependencyLanguage::Go, &[make(candidate)]).unwrap_err(),
                risk
            );
        }
        let unknown = [make(&unowned)];
        let result = adapt(&input, NativeDependencyLanguage::Go, &unknown).unwrap();
        assert!(result.observation().module_dependencies().is_empty());
        assert!(matches!(
            result.sites()[0].target(),
            NativeDependencySiteTarget::GoClosedPackage {
                ownership: NativeEndpointOwnership::OwnershipUnavailable { .. },
                ..
            }
        ));
        let conflicting = [make(&unowned), make(&one)];
        assert_eq!(
            adapt(&input, NativeDependencyLanguage::Go, &conflicting).unwrap_err(),
            NativeDependencyAdapterError::InvalidEndpoint
        );
        let selection = [make(&one)];
        assert_eq!(
            adapt(&input, NativeDependencyLanguage::Python, &selection).unwrap_err(),
            NativeDependencyAdapterError::InvalidEndpoint
        );
        let bad_context = NativeDependencyBatch {
            language: NativeDependencyLanguage::Go,
            context: NativeDependencyContext {
                authority_sha256: CONTEXT,
                ..SELECTED
            },
            observation_sha256: RECEIPT,
            endpoints: &selection,
        };
        assert_eq!(
            adapt_native_dependencies(&input, SELECTED, &bad_context).unwrap_err(),
            NativeDependencyAdapterError::BindingMismatch
        );
        let bad_coordinate = [NativeDependencyEndpoint {
            occurrence: NativeDependencyOccurrence {
                start_byte: 4,
                ..go_site(&app)
            },
            ..selection[0]
        }];
        assert_eq!(
            adapt(&input, NativeDependencyLanguage::Go, &bad_coordinate).unwrap_err(),
            NativeDependencyAdapterError::InvalidEndpoint
        );
        let over = vec![selection[0]; 4097];
        assert_eq!(
            adapt(&input, NativeDependencyLanguage::Go, &over).unwrap_err(),
            NativeDependencyAdapterError::ResourceLimit
        );
    }
}
