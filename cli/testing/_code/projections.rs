//! Explicit external projection materialization and refusal boundaries.
use fortress_core::bootstrap::{
    BootstrapDiscoveryOptions, apply_repository_bootstrap, discover_repository_bootstrap,
};
use fortress_core::migration_governance::MigrationEvaluator;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    base: PathBuf,
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "fortress-projection-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&base).unwrap();
        let root = base.join("repository");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='projection_cli_fixture'\nversion='0.1.0'\nedition='2024'\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn value() -> u32 { 7 }\n").unwrap();
        fs::write(root.join("build.rs"),"fn main() { std::fs::write(\"build-script-marker\",b\"executed\").unwrap(); panic!(\"must not execute\"); }\n").unwrap();
        let proposal = discover_repository_bootstrap(
            &root,
            &BootstrapDiscoveryOptions::new(
                Some("PF-PROJECTION-CLI".into()),
                Some("Projection CLI".into()),
            ),
        )
        .unwrap();
        apply_repository_bootstrap(&root, &proposal, false).unwrap();
        Self { base, root }
    }
    fn run(&self, destination: &std::path::Path, format: &str) -> (u8, Vec<u8>, Vec<u8>) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = fortress_cli::run(
            [
                "projections",
                self.root.to_str().unwrap(),
                "--output-dir",
                destination.to_str().unwrap(),
                "--format",
                format,
            ],
            &mut out,
            &mut err,
        )
        .unwrap();
        (code, out, err)
    }
    fn observe(&self) -> fortress_core::observation::SourceView {
        fortress_core::migration_adapter::CanonicalMigrationEvaluator
            .observe(&self.root)
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// `T-TF-CLI-0001-R30-001`
/// Fortress requirement: TF-CLI-0001-R30
#[test]
fn explicit_materialization_preserves_source_and_never_executes_build_scripts() {
    let fixture = Fixture::new();
    let before = fixture.observe();
    let first = fixture.base.join("first");
    let second = fixture.base.join("second");
    let (code, out, err) = fixture.run(&first, "json");
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
    let result: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(result["claim"], "STATIC_PROJECTIONS_ONLY");
    assert_eq!(result["execution"], "NOT_RUN");
    assert_eq!(result["certification"], "NOT_ISSUED");
    assert_eq!(result["authenticity"], "UNVERIFIED");
    let reference =
        fortress_core::audit::compile_repository_projection_bundle(&fixture.root).unwrap();
    assert_eq!(result["source_ref"], reference.source_ref);
    assert_eq!(
        result["files"].as_array().unwrap().len(),
        reference.projections.len()
    );
    for (logical, bytes) in reference.projections {
        let name = std::path::Path::new(&logical).file_name().unwrap();
        assert_eq!(fs::read(first.join(name)).unwrap(), bytes.as_bytes());
    }
    let (code, human, err) = fixture.run(&second, "human");
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
    assert!(
        String::from_utf8(human)
            .unwrap()
            .contains("STATIC_PROJECTIONS_ONLY")
    );
    let left: serde_json::Value =
        serde_json::from_slice(&fs::read(first.join("manifest.json")).unwrap()).unwrap();
    let right: serde_json::Value =
        serde_json::from_slice(&fs::read(second.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(left["files"], right["files"]);
    assert_eq!(before, fixture.observe());
    assert!(!fixture.root.join("build-script-marker").exists());
}

/// `T-TF-CLI-0001-R30-002`
/// Fortress requirement: TF-CLI-0001-R30
#[test]
fn unsafe_existing_and_traversing_destinations_are_not_overwritten() {
    let fixture = Fixture::new();
    let before = fixture.observe();
    let existing = fixture.base.join("existing");
    fs::create_dir(&existing).unwrap();
    fs::write(existing.join("user.txt"), b"preserved").unwrap();
    for destination in [
        fixture.root.join("generated"),
        existing.clone(),
        fixture.base.join("..").join("escape"),
        fixture.base.join("missing_parent").join("output"),
    ] {
        let (code, _, err) = fixture.run(&destination, "json");
        assert_ne!(code, 0);
        let error: serde_json::Value = serde_json::from_slice(&err).unwrap();
        assert_eq!(error["error"]["code"], "MATERIALIZATION_FAILED");
    }
    assert_eq!(fs::read(existing.join("user.txt")).unwrap(), b"preserved");
    assert_eq!(before, fixture.observe());
    assert!(!fixture.root.join("generated").exists());
    #[cfg(windows)]
    {
        let alias = fixture.base.join("REPOSITORY").join("generated");
        assert_ne!(fixture.run(&alias, "json").0, 0);
        assert!(!fixture.root.join("generated").exists());
    }
    #[cfg(unix)]
    {
        let link = fixture.base.join("linked_parent");
        std::os::unix::fs::symlink(&fixture.root, &link).unwrap();
        assert_ne!(fixture.run(&link.join("escaped"), "json").0, 0);
        assert!(!fixture.root.join("escaped").exists());
    }
}
