//! Actual-state controls for independently hosted Python lexical observations.

use std::fs;
use std::path::{Path, PathBuf};

use fortress_core::control_layout::{ControlLayout, EVIDENCE_ROOT};
use fortress_core::observation::{
    ObservationPolicy, SourceManifest, SourceView, observe_repository,
};
use fortress_core::portable::digest;
use fortress_core::python_observation::{
    PythonGrammar, PythonLexicalError, PythonLexicalMode, PythonLexicalOutcome,
    PythonLexicalProducer, PythonLexicalRequest, PythonObservationError, observe_python_lexical,
};
use serde_json::json;

const PATH: &str = "_code/source.py";
const SOURCE: &[u8] = b"value: int = 7\r\n";
const OTHER: &[u8] = b"original ancillary input\n";
const CONTEXT: &str = "sha256:f19e50baa1d1fd5a6df2123b2973d458d3806567b133d3192b5b2587b5e1376f";

struct Fixture {
    container: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let parent = std::env::temp_dir().canonicalize().expect("temporary root");
        let container = parent.join(format!(
            "fortress-python-native-{}-{name}",
            std::process::id()
        ));
        fs::create_dir(&container).expect("create owned fixture root");
        let root = container.join("project");
        Self::write_tree(&root);
        Self { container, root }
    }

    fn write_tree(root: &Path) {
        fs::create_dir(root).expect("create owned project");
        fs::create_dir(root.join("_code")).expect("create Code directory");
        fs::write(root.join(PATH), SOURCE).expect("write frozen source fixture");
        fs::write(root.join("note.txt"), OTHER).expect("write ancillary fixture");
    }

    fn configure(&self, content: &[u8]) {
        let control = self.root.join("__fortress");
        fs::create_dir_all(&control).expect("create owned control directory");
        fs::write(control.join(".fsconfig"), content).expect("write fixture authority");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let path = self
            .container
            .canonicalize()
            .expect("owned fixture resolves");
        assert_eq!(path, self.container);
        fs::remove_dir_all(path).expect("remove only owned fixture container");
    }
}

fn pin() -> PythonLexicalProducer {
    PythonLexicalProducer::new(
        PythonGrammar::Cpython313,
        format!("sha256:{}", "a".repeat(64)),
        format!("sha256:{}", "b".repeat(64)),
    )
    .expect("fixed fixture pins")
}

fn syntax_reply(
    request: &PythonLexicalRequest,
    selected: &[u8],
) -> Result<Vec<u8>, PythonObservationError> {
    assert_eq!(selected, SOURCE);
    assert_eq!(request.source_ref(), digest(SOURCE));
    let value = json!({
        "schema": "fortress-research/python-lexical-response/1",
        "id": request.id(),
        "source_ref": request.source_ref(),
        "byte_count": selected.len(),
        "runtime_ref": request.runtime_ref(),
        "worker_ref": request.worker_ref(),
        "mode": "SYNTAX",
        "outcome": "SYNTAX_ONLY",
        "reason": "LEXICAL_AND_MODULE_VALIDITY_NOT_ADMITTED",
        "stages": {
            "SYNTAX": {"status": "COMPLETE"},
            "LEXICAL_SCOPE": {"status": "NOT_RUN"},
            "MODULE_VALIDITY": {"status": "NOT_RUN"}
        },
        "observations": null,
        "target_execution": "NOT_RUN",
        "runtime_limitations": ["IMPORT_TARGETS", "RUNTIME_CALL_TARGETS", "EFFECTS", "EXECUTION"]
    });
    serde_json::to_vec(&value).map_err(|error| PythonLexicalError::Encoding(error).into())
}

/// T-AF-SNAPSHOT-GOVERNANCE-0001-R29-001
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn exact_original_source_and_selected_authority_bind_python_observation() {
    let fixture = Fixture::new("actual");
    let result = observe_python_lexical(
        &fixture.root,
        PATH,
        PythonLexicalMode::Syntax,
        &pin(),
        syntax_reply,
    )
    .expect("read-only exact original observation");
    assert_eq!(
        result.observation().outcome(),
        PythonLexicalOutcome::SyntaxOnly
    );
    assert_eq!(result.evaluation_key().program_context_digest(), CONTEXT);
    let policy = ObservationPolicy::new(
        [".git", EVIDENCE_ROOT]
            .into_iter()
            .chain(ControlLayout::standard().migration_record_roots()),
    )
    .unwrap();
    let observed = observe_repository(&fixture.root, &policy).unwrap();
    let expected_manifest = SourceManifest::from_observation(&observed, &policy).unwrap();
    assert_eq!(
        result.evaluation_key().source_manifest_digest(),
        expected_manifest.entries_digest()
    );
    let expected_view =
        SourceView::from_bytes([(PATH, SOURCE.to_vec()), ("note.txt", OTHER.to_vec())]).unwrap();
    let retained: serde_json::Value =
        serde_json::from_slice(&result.observation().to_canonical_json().unwrap()).unwrap();
    assert_eq!(
        retained["request"]["source_view_ref"],
        expected_view.digest()
    );
    assert_eq!(
        retained["request"]["evaluation_ref"],
        result.evaluation_key().digest()
    );
    assert_eq!(retained["report"]["target_execution"], "NOT_RUN");
    let absent_authority = result.evaluation_key().authority_binding_digest();
    assert!(absent_authority.starts_with("sha256:"));

    let current_config = br#"{"$schema":"urn:fortress:schema:v3:project-configuration","schema_version":3,"observation_exclusions":[],"logical_modules":[]}"#;
    fixture.configure(current_config);
    fs::write(
        fixture.root.join("contract.json"),
        br#"{"$schema":"urn:fortress:schema:v2:module-contract","schema_version":2,
"id":"PF-PYTHON-FIXTURE","display_name":"Python lexical fixture",
"ecosystem":{"repository_grammar":1,"standard":{"id":"STD-FORTRESS-ENGINEERING","edition":"1.0.0-draft.2"}},
"provides":[],"requires":[],"relationships":[],"constraints":[],"guarantees":[],"features":[],"behavior":[]}"#,
    )
    .unwrap();
    let declared = observe_python_lexical(
        &fixture.root,
        PATH,
        PythonLexicalMode::Syntax,
        &pin(),
        syntax_reply,
    )
    .expect("selected declared original authority");
    assert_eq!(declared.evaluation_key().program_context_digest(), CONTEXT);
    assert_ne!(
        declared.evaluation_key().authority_binding_digest(),
        absent_authority
    );
    assert_ne!(
        declared.evaluation_key().source_manifest_digest(),
        expected_manifest.entries_digest()
    );
    assert_eq!(fs::read(fixture.root.join(PATH)).unwrap(), SOURCE);
    assert_eq!(fs::read(fixture.root.join("note.txt")).unwrap(), OTHER);
    assert_eq!(
        fs::read(fixture.root.join("__fortress/.fsconfig")).unwrap(),
        current_config
    );
}

/// T-AF-SNAPSHOT-GOVERNANCE-0001-R29-002
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn changes_outside_the_selected_file_prevent_python_publication() {
    let fixture = Fixture::new("whole-view");
    let result = observe_python_lexical(
        &fixture.root,
        PATH,
        PythonLexicalMode::Syntax,
        &pin(),
        |request, bytes| {
            let original = syntax_reply(request, bytes)?;
            fs::write(fixture.root.join("note.txt"), "changed ancillary input\n").unwrap();
            Ok(original)
        },
    );
    assert!(matches!(result, Err(PythonObservationError::SourceChanged)));
    let result = observe_python_lexical(
        &fixture.root,
        PATH,
        PythonLexicalMode::Syntax,
        &pin(),
        |request, bytes| {
            let original = syntax_reply(request, bytes)?;
            fixture.configure(b"new attempted authority");
            Ok(original)
        },
    );
    assert!(matches!(result, Err(PythonObservationError::SourceChanged)));
    assert_eq!(fs::read(fixture.root.join(PATH)).unwrap(), SOURCE);
}

/// T-AF-SNAPSHOT-GOVERNANCE-0001-R29-003
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn replacement_directory_with_equal_bytes_prevents_python_publication() {
    let fixture = Fixture::new("directory");
    let result = observe_python_lexical(
        &fixture.root,
        PATH,
        PythonLexicalMode::Syntax,
        &pin(),
        |request, bytes| {
            let original = syntax_reply(request, bytes)?;
            fs::rename(&fixture.root, fixture.container.join("retained-original")).unwrap();
            Fixture::write_tree(&fixture.root);
            Ok(original)
        },
    );
    assert!(matches!(result, Err(PythonObservationError::SourceChanged)));
}

/// T-AF-SNAPSHOT-GOVERNANCE-0001-R29-004
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn invalid_and_excluded_original_authority_prevent_python_dispatch() {
    let fixture = Fixture::new("authority");
    for rejected in [
        b"not valid project JSON".as_slice(),
        br#"{"$schema":"urn:fortress:schema:v3:project-configuration","schema_version":3,"observation_exclusions":["note.txt"],"logical_modules":[]}"#,
    ] {
        fixture.configure(rejected);
        let result = observe_python_lexical(
            &fixture.root,
            PATH,
            PythonLexicalMode::Syntax,
            &pin(),
            |_, _| panic!("unavailable original authority must refuse worker dispatch"),
        );
        assert!(matches!(result, Err(PythonObservationError::SourceUnavailable(_))));
    }
}

/// T-AF-SNAPSHOT-GOVERNANCE-0001-R29-005
/// Fortress requirement: AF-SNAPSHOT-GOVERNANCE-0001-R29
#[test]
fn candidate_bound_python_reply_cannot_be_used_for_actual_source() {
    let fixture = Fixture::new("candidate");
    let original = observe_python_lexical(
        &fixture.root,
        PATH,
        PythonLexicalMode::Syntax,
        &pin(),
        syntax_reply,
    )
    .unwrap();
    let proposed = SourceView::from_bytes([
        (PATH, SOURCE.to_vec()),
        ("note.txt", b"hypothetical ancillary replacement\n".to_vec()),
    ])
    .unwrap();
    let candidate = PythonLexicalRequest::for_source(
        &proposed,
        original.evaluation_key(),
        PATH,
        PythonLexicalMode::Syntax,
        pin(),
    )
    .unwrap();
    let result = observe_python_lexical(
        &fixture.root,
        PATH,
        PythonLexicalMode::Syntax,
        &pin(),
        |actual, bytes| {
            assert_ne!(actual.id(), candidate.id());
            syntax_reply(&candidate, bytes)
        },
    );
    assert!(matches!(
        result,
        Err(PythonObservationError::Lexical(
            PythonLexicalError::InvalidBinding
        ))
    ));
    assert_eq!(fs::read(fixture.root.join("note.txt")).unwrap(), OTHER);
}
