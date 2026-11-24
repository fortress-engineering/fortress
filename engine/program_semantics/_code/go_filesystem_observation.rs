//! Admits bounded Go standard library call facts from an exact process exchange.

use std::cmp::Reverse;

use serde::{Deserialize, Deserializer, Serialize};

use super::{
    ExactClosedPackage, GoCollectorPin, GoObservationError, GoRequest, SourceIdentity, Span,
    admit_go, digest, sha256,
};
use crate::wire::parse_strict_json_bytes;

const PRODUCER: &str = "fortress.go-filesystem@0.1.0";
const MAX_CALLS: usize = 64;
const MAX_RESPONSE_BYTES: usize = 32 << 10;

/// Independently selected SDK sources and ordered standard-library export set.
#[derive(Clone, Copy)]
pub struct GoFilesystemLibraryPin<'a> {
    /// Digest of the reviewed target-specific standard `os` package sources.
    pub package_source_ref: &'a str,
    /// Digest of the reviewed cgo-disabled standard export set in path order.
    pub export_set_ref: &'a str,
}

/// Availability of the closed compiler call inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(
    tag = "status",
    content = "reason",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum GoFilesystemDisposition {
    /// The worker processed the admitted source under the selected SDK context.
    Observed,
    /// The worker could not produce call facts for the admitted scope.
    Unavailable(GoFilesystemUnavailable),
}

/// Recognized reasons the worker could not produce call facts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GoFilesystemUnavailable {
    /// The worker's target is incompatible with the closed request.
    ClosedPackageContextUnavailable,
    /// The source requires independently selected build inputs.
    BuildContextRequired,
    /// Source syntax could not be parsed.
    GoParseFailure,
    /// A compiler directive requires a separate admitted context.
    CompilerDirectiveContextRequired,
    /// The native syntax tree exceeded its bound.
    GoAstLimit,
    /// The selected standard export context is missing or incompatible.
    StandardExportContextUnavailable,
    /// The pinned standard package export could not be read or decoded.
    StandardExportUnavailable,
    /// The standard declaration could not be established in that export.
    StandardDeclarationUnavailable,
    /// The single file could not be type checked within the admitted scope.
    GoTypeContextUnavailable,
    /// The native call inventory exceeded its bound.
    CallInventoryLimit,
    /// The selected declaration identity could not be encoded.
    DeclarationIdentityUnavailable,
}

/// Compiler resolution of a physical call expression.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GoFilesystemCallResolution {
    /// The callee is the selected SDK's `os.WriteFile` declaration.
    ResolvedStandardLibrary,
    /// The compiler selected a different project function or method.
    LocalOrShadowed,
    /// Resolution to the selected declaration is unavailable.
    Unresolved,
}

/// A call occurrence verified against the one admitted ordinary source file.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoFilesystemCall {
    span: Span,
    resolution: GoFilesystemCallResolution,
}

impl GoFilesystemCall {
    /// Zero-based first byte of the expression.
    #[must_use]
    pub fn start_byte(&self) -> usize {
        self.span.start_byte
    }

    /// Zero-based exclusive final byte of the expression.
    #[must_use]
    pub fn end_byte(&self) -> usize {
        self.span.end_byte
    }

    /// The selected compiler resolution.
    #[must_use]
    pub fn resolution(&self) -> GoFilesystemCallResolution {
        self.resolution
    }
}

/// Call facts from a verified live exchange, scoped to an exact source and SDK.
///
/// This value has no portable admission path. Its serializable form reports
/// the input binding and available facts without establishing runtime effects,
/// coverage outside the closed file, enforcement, or certification.
#[derive(Serialize)]
pub struct GoNativeFilesystemObservation {
    binding_ref: String,
    request_ref: String,
    response_ref: String,
    source: SourceIdentity,
    selected_package_source_ref: String,
    selected_export_set_ref: String,
    disposition: GoFilesystemDisposition,
    declaration_ref: Option<String>,
    calls: Vec<GoFilesystemCall>,
}

impl GoNativeFilesystemObservation {
    /// The call inventory disposition for this exact exchange.
    #[must_use]
    pub fn disposition(&self) -> GoFilesystemDisposition {
        self.disposition
    }

    /// Exact repository-relative source path, even when processing was unavailable.
    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source.path
    }

    /// Digest of the original physical source bytes.
    #[must_use]
    pub fn source_ref(&self) -> &str {
        &self.source.sha256
    }

    /// Identity of the exact source, original authority, process, and selected SDK inputs.
    #[must_use]
    pub fn binding_ref(&self) -> &str {
        &self.binding_ref
    }

    /// Digest of the exact native response frame.
    #[must_use]
    pub fn response_ref(&self) -> &str {
        &self.response_ref
    }

    /// SDK declaration identity derived under the selected pins when observed.
    #[must_use]
    pub fn declaration_ref(&self) -> Option<&str> {
        self.declaration_ref.as_deref()
    }

    /// Admitted call facts. An empty slice carries no runtime conclusion.
    #[must_use]
    pub fn calls(&self) -> &[GoFilesystemCall] {
        &self.calls
    }
}

#[derive(Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
enum Response {
    Observed {
        schema_version: u16,
        producer: String,
        request_ref: String,
        package_source_ref: String,
        export_set_ref: String,
        declaration_ref: String,
        source: SourceIdentity,
        calls: Vec<GoFilesystemCall>,
    },
    Unavailable {
        schema_version: u16,
        producer: String,
        request_ref: String,
        reason: GoFilesystemUnavailable,
        #[serde(default, deserialize_with = "present_source")]
        source: Option<SourceIdentity>,
        calls: Vec<GoFilesystemCall>,
    },
}

fn present_source<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<SourceIdentity>, D::Error> {
    SourceIdentity::deserialize(deserializer).map(Some)
}

pub(crate) struct GoFilesystemRequest<'a> {
    base: GoRequest<'a>,
    library: GoFilesystemLibraryPin<'a>,
    binding_ref: String,
    declaration_ref: String,
}

pub(crate) fn admit_go_filesystem<'a>(
    selection: ExactClosedPackage<'a>,
    process: &'a GoCollectorPin<'a>,
    library: GoFilesystemLibraryPin<'a>,
) -> Result<GoFilesystemRequest<'a>, GoObservationError> {
    if !digest(library.package_source_ref) || !digest(library.export_set_ref) {
        return Err(GoObservationError::InvalidTrustedBinding);
    }
    if !selection.actual || selection.go_version != "go1.22" || selection.package_path == "os" {
        return Err(GoObservationError::UnsupportedContext);
    }
    let base = admit_go(selection, process)?;
    if base.context.source_inventory.len() != 1 {
        return Err(GoObservationError::UnsupportedContext);
    }
    let declaration = [
        "os",
        "WriteFile",
        library.package_source_ref,
        library.export_set_ref,
        process.go_toolchain,
        selection.target_os,
        selection.target_arch,
    ];
    // All fields are admitted ASCII strings with identical Go and Rust escaping.
    let declaration_bytes =
        serde_json::to_vec(&declaration).map_err(|_| GoObservationError::WireEncoding)?;
    let binding_bytes = serde_json_canonicalizer::to_vec(&(
        PRODUCER,
        &base.binding_sha256,
        library.package_source_ref,
        library.export_set_ref,
    ))
    .map_err(|_| GoObservationError::WireEncoding)?;
    Ok(GoFilesystemRequest {
        base,
        library,
        binding_ref: sha256(&binding_bytes),
        declaration_ref: sha256(&declaration_bytes),
    })
}

impl GoFilesystemRequest<'_> {
    pub(crate) fn source_path(&self) -> &str {
        &self.base.context.source_inventory[0].path
    }

    pub(crate) fn request_bytes(&self) -> &[u8] {
        self.base.request_bytes()
    }

    pub(crate) fn verify(
        &self,
        launched: &GoCollectorPin<'_>,
        stdout: &[u8],
    ) -> Result<GoNativeFilesystemObservation, GoObservationError> {
        if stdout.len() > MAX_RESPONSE_BYTES {
            return Err(GoObservationError::ResourceLimit);
        }
        let line = self.base.verify_transport(launched, stdout)?;
        let response: Response =
            parse_strict_json_bytes(line).map_err(|_| GoObservationError::InvalidResponse)?;
        let [selected] = self.base.context.source_inventory.as_slice() else {
            return Err(GoObservationError::InvalidResponse);
        };
        let (disposition, declaration_ref, calls) = match response {
            Response::Observed {
                schema_version,
                producer,
                request_ref,
                package_source_ref,
                export_set_ref,
                declaration_ref,
                source,
                calls,
            } => {
                self.verify_header(schema_version, &producer, &request_ref)?;
                if &source != selected
                    || package_source_ref != self.library.package_source_ref
                    || export_set_ref != self.library.export_set_ref
                    || declaration_ref != self.declaration_ref
                {
                    return Err(GoObservationError::InvalidResponse);
                }
                self.verify_calls(&calls)?;
                (
                    GoFilesystemDisposition::Observed,
                    Some(declaration_ref),
                    calls,
                )
            }
            Response::Unavailable {
                schema_version,
                producer,
                request_ref,
                reason,
                source,
                calls,
            } => {
                self.verify_header(schema_version, &producer, &request_ref)?;
                let expected = (reason != GoFilesystemUnavailable::ClosedPackageContextUnavailable)
                    .then_some(selected);
                if !calls.is_empty() || source.as_ref() != expected {
                    return Err(GoObservationError::InvalidResponse);
                }
                (GoFilesystemDisposition::Unavailable(reason), None, calls)
            }
        };
        Ok(GoNativeFilesystemObservation {
            binding_ref: self.binding_ref.clone(),
            request_ref: self.base.request_sha256.clone(),
            response_ref: sha256(stdout),
            source: SourceIdentity {
                path: selected.path.clone(),
                sha256: selected.sha256.clone(),
            },
            selected_package_source_ref: self.library.package_source_ref.into(),
            selected_export_set_ref: self.library.export_set_ref.into(),
            disposition,
            declaration_ref,
            calls,
        })
    }

    fn verify_header(
        &self,
        schema_version: u16,
        producer: &str,
        request_ref: &str,
    ) -> Result<(), GoObservationError> {
        if schema_version != 1 || producer != PRODUCER || request_ref != self.base.request_sha256 {
            return Err(GoObservationError::InvalidResponse);
        }
        Ok(())
    }

    fn verify_calls(&self, calls: &[GoFilesystemCall]) -> Result<(), GoObservationError> {
        if calls.len() > MAX_CALLS {
            return Err(GoObservationError::ResourceLimit);
        }
        let mut previous = None;
        for call in calls {
            let text = self.base.span(&call.span)?;
            let position = (call.start_byte(), Reverse(call.end_byte()));
            // Walk order is physical order, with outer call first at a shared start.
            if !text.ends_with(')') || !text.contains('(') || previous >= Some(position) {
                return Err(GoObservationError::InvalidResponse);
            }
            previous = Some(position);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::{Value, json};

    use super::*;
    use crate::observation::SourceView;

    const SOURCE: &[u8] = b"package effects\nimport \"os\"\nfunc witness() error { return os.WriteFile(\"file\", nil, 0600) }\n";
    const SOURCE_REF: &str =
        "sha256:44397e0404a4e35e25db20dfce18dc34807eb94ce579897c9035cb6fda90bdfe";
    const REQUEST_REF: &str =
        "sha256:91040921e00ba0f716c96959e3af7d394c10f3445f5efd0f914a463335b2f3e8";
    const DECLARATION_REF: &str =
        "sha256:afcf83f942fbf1023428bbd4a1e8d940ebff4326fd98d6a4f7d4dcbe6a17fd42";
    const HOST: GoCollectorPin<'static> = GoCollectorPin {
        executable_sha256: "sha256:d9650e5d65c1871ad072ce215ff66378a5b1f4495eb34ec6c6d677fe34781075",
        supervisor_context_sha256: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        go_toolchain: "go1.22.12",
    };
    const LIBRARY: GoFilesystemLibraryPin<'static> = GoFilesystemLibraryPin {
        package_source_ref: "sha256:8f61ebb242bc4c60ebcaf6a96015ff67d0ac84d3441da63bd6c185eda13fc226",
        export_set_ref: "sha256:4ff2871ac521be941d7da0eaef51d1a90a6e30a504774a8b043a03943e1798bc",
    };

    fn view() -> SourceView {
        SourceView::from_bytes([("fixture.go", SOURCE.to_vec())]).unwrap()
    }

    fn selection<'a>(
        source: &'a SourceView,
        contracts: &'a BTreeSet<String>,
    ) -> ExactClosedPackage<'a> {
        ExactClosedPackage {
            source,
            source_fingerprint: source.digest(),
            authority_digest: HOST.supervisor_context_sha256,
            logical_contracts: contracts,
            actual: true,
            directory: "",
            package_path: "fixture.local/effects",
            go_version: "go1.22",
            target_os: "windows",
            target_arch: "amd64",
        }
    }

    fn observed() -> Value {
        json!({
            "schema_version": 1,
            "producer": PRODUCER,
            "request_ref": REQUEST_REF,
            "status": "OBSERVED",
            "package_source_ref": LIBRARY.package_source_ref,
            "export_set_ref": LIBRARY.export_set_ref,
            "declaration_ref": DECLARATION_REF,
            "source": { "path": "fixture.go", "sha256": SOURCE_REF },
            "calls": [{
                "span": {
                    "path": "fixture.go",
                    "start_byte": 58,
                    "end_byte": 89,
                    "start_line": 3,
                    "start_byte_column": 31
                },
                "resolution": "RESOLVED_STANDARD_LIBRARY"
            }]
        })
    }

    fn unavailable() -> Value {
        json!({
            "schema_version": 1,
            "producer": PRODUCER,
            "request_ref": REQUEST_REF,
            "status": "UNAVAILABLE",
            "reason": "GO_TYPE_CONTEXT_UNAVAILABLE",
            "source": { "path": "fixture.go", "sha256": SOURCE_REF },
            "calls": []
        })
    }

    fn frame(value: &Value) -> Vec<u8> {
        let mut frame = serde_json::to_vec(value).unwrap();
        frame.push(b'\n');
        frame
    }

    /// `T-GO-FILESYSTEM-OCCURRENCE-001`
    /// Fortress classification: infrastructure
    #[test]
    fn reports_exact_standard_declaration_and_physical_occurrence() {
        let source = view();
        let contracts = BTreeSet::new();
        let request = admit_go_filesystem(selection(&source, &contracts), &HOST, LIBRARY).unwrap();
        assert_eq!(sha256(request.request_bytes()), REQUEST_REF);
        let raw = frame(&observed());
        let answer = request.verify(&HOST, &raw).unwrap();
        assert_eq!(answer.disposition(), GoFilesystemDisposition::Observed);
        assert_eq!(answer.source_path(), "fixture.go");
        assert_eq!(answer.source_ref(), SOURCE_REF);
        assert_eq!(answer.request_ref.as_str(), REQUEST_REF);
        assert_eq!(answer.response_ref(), sha256(&raw));
        assert!(digest(answer.binding_ref()));
        assert_eq!(answer.declaration_ref(), Some(DECLARATION_REF));
        let [call] = answer.calls() else {
            panic!("expected one call");
        };
        assert_eq!(
            call.resolution(),
            GoFilesystemCallResolution::ResolvedStandardLibrary
        );
        assert_eq!(call.span.path.as_str(), "fixture.go");
        assert_eq!((call.span.start_line, call.span.start_byte_column), (3, 31));
        assert_eq!(
            &SOURCE[call.start_byte()..call.end_byte()],
            b"os.WriteFile(\"file\", nil, 0600)"
        );
    }

    /// `T-GO-FILESYSTEM-IDENTITY-001`
    /// Fortress classification: infrastructure
    #[test]
    fn refuses_wrong_header_sdk_source_and_call_identity() {
        let source = view();
        let contracts = BTreeSet::new();
        let request = admit_go_filesystem(selection(&source, &contracts), &HOST, LIBRARY).unwrap();
        for (pointer, value) in [
            ("/schema_version", json!(2)),
            ("/status", json!("PASS")),
            ("/producer", json!("candidate-supplied")),
            ("/request_ref", json!(SOURCE_REF)),
            ("/package_source_ref", json!(SOURCE_REF)),
            ("/export_set_ref", json!(SOURCE_REF)),
            ("/declaration_ref", json!(SOURCE_REF)),
            ("/source/path", json!("alternate.go")),
            ("/source/sha256", json!(DECLARATION_REF)),
            ("/calls/0/span/path", json!("alternate.go")),
            ("/calls/0/span/start_line", json!(4)),
            ("/calls/0/span/start_byte_column", json!(30)),
            ("/calls/0/span/end_byte", json!(100)),
            ("/calls/0/span/end_byte", json!(58)),
            ("/calls/0/resolution", json!("APPROVED")),
        ] {
            let mut value_with_mutation = observed();
            *value_with_mutation.pointer_mut(pointer).unwrap() = value;
            assert!(
                matches!(
                    request.verify(&HOST, &frame(&value_with_mutation)),
                    Err(GoObservationError::InvalidResponse)
                ),
                "{pointer}"
            );
        }
        let altered = GoFilesystemLibraryPin {
            package_source_ref: SOURCE_REF,
            ..LIBRARY
        };
        let alternate_request =
            admit_go_filesystem(selection(&source, &contracts), &HOST, altered).unwrap();
        assert!(matches!(
            alternate_request.verify(&HOST, &frame(&observed())),
            Err(GoObservationError::InvalidResponse)
        ));
    }

    /// `T-GO-FILESYSTEM-WIRE-001`
    /// Fortress classification: infrastructure
    #[test]
    fn rejects_duplicate_bounded_and_unrecognized_wire_records() {
        let source = view();
        let contracts = BTreeSet::new();
        let request = admit_go_filesystem(selection(&source, &contracts), &HOST, LIBRARY).unwrap();
        let mut value = observed();
        value["certification"] = json!("PASS");
        assert!(matches!(
            request.verify(&HOST, &frame(&value)),
            Err(GoObservationError::InvalidResponse)
        ));
        let mut value = observed();
        let row = value["calls"][0].clone();
        value["calls"] = json!([row.clone(), row.clone()]);
        assert!(matches!(
            request.verify(&HOST, &frame(&value)),
            Err(GoObservationError::InvalidResponse)
        ));
        value["calls"] = json!(vec![row; MAX_CALLS + 1]);
        assert!(matches!(
            request.verify(&HOST, &frame(&value)),
            Err(GoObservationError::ResourceLimit)
        ));
        let duplicate = String::from_utf8(frame(&observed())).unwrap().replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
        );
        assert!(request.verify(&HOST, duplicate.as_bytes()).is_err());

        let mut multiple_frames = frame(&observed());
        multiple_frames.extend_from_slice(&frame(&observed()));
        assert!(matches!(
            request.verify(&HOST, &multiple_frames),
            Err(GoObservationError::InvalidResponse)
        ));
    }

    /// `T-GO-FILESYSTEM-UNAVAILABLE-001`
    /// Fortress classification: infrastructure
    #[test]
    fn preserves_unavailability_with_no_positive_call_facts() {
        let source = view();
        let contracts = BTreeSet::new();
        let request = admit_go_filesystem(selection(&source, &contracts), &HOST, LIBRARY).unwrap();
        let raw = frame(&unavailable());
        let answer = request.verify(&HOST, &raw).unwrap();
        assert_eq!(
            answer.disposition(),
            GoFilesystemDisposition::Unavailable(GoFilesystemUnavailable::GoTypeContextUnavailable)
        );
        assert_eq!(answer.source_ref(), SOURCE_REF);
        assert_eq!(answer.declaration_ref(), None);
        assert!(answer.calls().is_empty());

        let mut no_matching_target = unavailable();
        no_matching_target.as_object_mut().unwrap().remove("source");
        no_matching_target["reason"] = json!("CLOSED_PACKAGE_CONTEXT_UNAVAILABLE");
        let answer = request.verify(&HOST, &frame(&no_matching_target)).unwrap();
        assert_eq!(answer.source_path(), "fixture.go");
        assert!(answer.calls().is_empty());

        for (field, mutation) in [
            ("reason", json!("CLAIMED_COMPATIBLE")),
            ("declaration_ref", json!(DECLARATION_REF)),
            ("source", Value::Null),
            ("calls", observed()["calls"].clone()),
        ] {
            let mut bad = unavailable();
            bad[field] = mutation;
            assert!(matches!(
                request.verify(&HOST, &frame(&bad)),
                Err(GoObservationError::InvalidResponse)
            ));
        }
    }

    /// `T-GO-FILESYSTEM-RESPONSE-BINDING-001`
    /// Fortress classification: infrastructure
    #[test]
    fn admits_only_one_actual_source_and_exact_trusted_process() {
        let source = view();
        let contracts = BTreeSet::new();
        let mut closed = selection(&source, &contracts);
        closed.actual = false;
        assert!(matches!(
            admit_go_filesystem(closed, &HOST, LIBRARY),
            Err(GoObservationError::UnsupportedContext)
        ));
        let two_files = SourceView::from_bytes([
            ("fixture.go", SOURCE.to_vec()),
            ("another.go", b"package effects\n".to_vec()),
        ])
        .unwrap();
        assert!(matches!(
            admit_go_filesystem(selection(&two_files, &contracts), &HOST, LIBRARY),
            Err(GoObservationError::UnsupportedContext)
        ));
        let bad_library = GoFilesystemLibraryPin {
            export_set_ref: "candidate",
            ..LIBRARY
        };
        assert!(matches!(
            admit_go_filesystem(selection(&source, &contracts), &HOST, bad_library),
            Err(GoObservationError::InvalidTrustedBinding)
        ));
        let request = admit_go_filesystem(selection(&source, &contracts), &HOST, LIBRARY).unwrap();
        let unmatched = GoCollectorPin {
            executable_sha256: SOURCE_REF,
            ..HOST
        };
        assert!(matches!(
            request.verify(&unmatched, &frame(&observed())),
            Err(GoObservationError::UnmatchedExecution)
        ));
    }
}
