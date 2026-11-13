//! Adversarial boundary controls without repository code execution.

use fortress_core::observation::{
    ObservationPolicy, admit_rust, observe_repository, observe_source_manifest, physical,
};
use fortress_core::wire::{JsonAdmissionLimits, admit_json, parse_strict_json};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fortress-boundary-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("fixture");
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-001`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn json_budgets_precede_decoder_allocation_and_are_global() {
    let limits = JsonAdmissionLimits {
        bytes: 1024,
        depth: 4,
        nodes: 5,
        token_bytes: 32,
    };
    for bad in [
        "[[[[[0]]]]]".to_string(),
        "[0,0,0,0,0]".to_string(),
        format!("\"{}\"", "a".repeat(33)),
        " ".repeat(1025),
    ] {
        assert!(
            admit_json(bad.as_bytes(), limits)
                .unwrap_err()
                .to_string()
                .contains("RESOURCE_LIMIT")
        );
    }
    assert!(admit_json(br#"{"x":"[[[[[","y":0}"#, limits).is_ok());
    assert!(parse_strict_json::<serde_json::Value>(r#"{"x":1,"x":2}"#).is_err());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-002`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn retained_file_identity_rejects_equal_length_replacement() {
    let root = Fixture::new();
    let path = root.0.join("source");
    fs::write(&path, b"base").unwrap();
    let retained = physical::open_regular(&path).unwrap();
    let before = retained.metadata().unwrap();
    fs::rename(&path, root.0.join("old")).unwrap();
    fs::write(&path, b"base").unwrap();
    assert!(physical::verify_regular(&path, &retained, &before).is_err());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-003`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn rust_recursion_and_operator_exhaustion_fail_before_semantic_parsing() {
    for source in [
        format!("{}0{}", "(".repeat(129), ")".repeat(129)),
        format!("fn f() {{ {}0; }}", "1+".repeat(257)),
        "/*".repeat(129),
        format!("fn f() {{ {}0 }}", "return ".repeat(257)),
        format!("type X = {}u8{};", "Vec<".repeat(129), ">".repeat(129)),
    ] {
        assert!(admit_rust(&source).unwrap_err().contains("RESOURCE_LIMIT"));
    }
    assert!(
        admit_rust(&format!(
            "fn f<'a>(x: &'a str) {{ let _ = r###\"{}\"###; let _ = '\\u{{28}}'; }}",
            "(".repeat(500)
        ))
        .is_ok()
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-004`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn malformed_mutations_never_panic_or_silently_accept_duplicate_identity() {
    let seed = br#"{"a":[true,false,null,1],"b":"\"["}"#;
    for position in 0..seed.len() {
        for replacement in [0, b'"', b'[', b'}', b'\\', 255] {
            let mut input = seed.to_vec();
            input[position] = replacement;
            if let Ok(text) = std::str::from_utf8(&input) {
                let _ = parse_strict_json::<serde_json::Value>(text);
            }
        }
    }
    assert!(parse_strict_json::<serde_json::Value>(r#"{"id":"x","id":"y"}"#).is_err());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-005`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn inspection_does_not_invoke_build_scripts_or_executables() {
    let root = Fixture::new();
    fs::write(
        root.0.join("Cargo.toml"),
        b"[package]\nname='untrusted'\nversion='0.1.0'\nbuild='build.rs'\n",
    )
    .unwrap();
    fs::write(
        root.0.join("build.rs"),
        b"compile_error!(\"must never execute\");",
    )
    .unwrap();
    fs::write(root.0.join("python.exe"), b"untrusted executable sentinel").unwrap();
    let first = observe_repository(&root.0, &ObservationPolicy::default()).unwrap();
    assert_eq!(first.files().len(), 3);
    fortress_core::bootstrap::discover_repository_bootstrap(
        &root.0,
        &fortress_core::bootstrap::BootstrapDiscoveryOptions::new(
            Some("PF-UNTRUSTED".into()),
            Some("Untrusted".into()),
        ),
    )
    .expect("read-only discovery never invokes Cargo or the build script");
    let _query = fortress_core::query::load_repository_query(
        &root.0,
        &fortress_core::query::QueryLoadOptions::default(),
    )
    .unwrap();

    assert_eq!(
        first,
        observe_repository(&root.0, &ObservationPolicy::default()).unwrap()
    );
    assert_eq!(
        observe_source_manifest(&root.0, &ObservationPolicy::default())
            .unwrap()
            .entries()
            .len(),
        3
    );
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-006`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn linux_case_collision_and_symlink_roots_are_rejected() {
    assert!(!fortress_core::observation::is_canonical_relative_path(
        "../outside"
    ));
    #[cfg(unix)]
    {
        let root = Fixture::new();
        let outside = Fixture::new();
        fs::write(root.0.join("A"), b"a").unwrap();
        fs::write(root.0.join("a"), b"b").unwrap();
        assert!(observe_repository(&root.0, &ObservationPolicy::default()).is_err());
        assert!(observe_source_manifest(&root.0, &ObservationPolicy::default()).is_err());
        let link = root.0.join("linked");
        std::os::unix::fs::symlink(&outside.0, &link).unwrap();
        assert!(observe_repository(&link, &ObservationPolicy::default()).is_err());
        assert!(observe_source_manifest(&link, &ObservationPolicy::default()).is_err());
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-007`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn windows_junction_roots_are_rejected_without_traversal() {
    #[cfg(windows)]
    {
        let root = Fixture::new();
        let outside = Fixture::new();
        let link = root.0.join("linked");
        // cmd is used only to create a disposable fixture junction, never to delete it.
        let status = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside.0)
            .status()
            .unwrap();
        assert!(status.success());
        let strict = observe_repository(&link, &ObservationPolicy::default());
        let manifest = observe_source_manifest(&link, &ObservationPolicy::default());
        fs::remove_dir(&link).unwrap();
        assert!(strict.is_err());
        assert!(manifest.is_err());
    }
    #[cfg(unix)]
    {
        let root = Fixture::new();
        let path = root.0.join("linked");
        std::os::unix::fs::symlink("missing", &path).unwrap();
        assert!(physical::open_regular(&path).is_err());
    }
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-010`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn source_admission_preserves_the_complete_current_rust_corpus() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let policy = ObservationPolicy::new([".git", "__fortress/evidence", "target"]).unwrap();
    let observation = observe_repository(&root, &policy).unwrap();
    let mut count = 0;
    for file in observation.files().iter().filter(|file| {
        std::path::Path::new(file.path())
            .extension()
            .is_some_and(|extension| extension == "rs")
    }) {
        let bytes = fs::read(root.join(file.path())).unwrap();
        let source = std::str::from_utf8(&bytes).unwrap();
        admit_rust(source).unwrap_or_else(|error| panic!("{}: {error}", file.path()));
        count += 1;
    }
    assert!(count > 100);
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-011`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn untrusted_display_controls_cannot_rewrite_readable_inspection() {
    let message = "violation\u{1b}[2J\r\n\u{202e}text";
    let value = serde_json::json!({"message": message});
    let rendered = fortress_core::query::render_inspection_value(&value);
    assert!(!rendered.contains('\u{1b}'));
    assert!(!rendered.contains('\r'));
    assert!(!rendered.contains('\u{202e}'));
    assert!(rendered.contains("\\n"));
    assert_eq!(value["message"], message);
}

fn oversized_manifest_input()
-> fortress_core::implementation_observation::ImplementationObservationInput {
    use fortress_core::implementation_observation::{
        ImplementationObservationInput, ModuleTerritory, SnapshotBoundFile,
    };
    let bytes = vec![b' '; fortress_core::observation::MAX_SOURCE_UNIT_BYTES + 1];
    ImplementationObservationInput::new(
        "sha256:fixture",
        vec![SnapshotBoundFile::from_bytes("Cargo.toml", bytes)],
        vec![ModuleTerritory::new("PF-BOUNDARY", "")],
    )
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-012`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn program_manifest_bytes_are_admitted_before_toml_allocation() {
    use fortress_core::program_semantics::{ProgramSemanticInput, compile_program_semantic_model};
    let input = ProgramSemanticInput::new(
        "PF-BOUNDARY",
        oversized_manifest_input(),
        Vec::new(),
        Vec::new(),
    );
    let error = compile_program_semantic_model(&input).unwrap_err();
    assert!(error.to_string().contains("RESOURCE_LIMIT"));
    let recursive = format!("key = {}0{}", "[".repeat(512), "]".repeat(512));
    assert!(toml::from_str::<toml::Value>(&recursive).is_err());
}

/// `T-AF-SNAPSHOT-GOVERNANCE-0001-R24-013`
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R24
#[test]
fn implementation_manifest_bytes_are_admitted_before_toml_allocation() {
    let error = fortress_core::implementation_observation::observe_cargo_analysis_territories(
        &oversized_manifest_input(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("RESOURCE_LIMIT"));
}
