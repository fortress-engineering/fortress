//! Exact test declaration observations in a separately pinned Go build context.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::build_selection::{Disposition, GoBuildRequest, admit_go_build};
use super::{
    Context, ExactClosedPackage, GoBuildContext, GoBuildTestMode, GoCollectorPin,
    GoObservationError, MAX_RECORDS, Span, display_name, sha256,
};
use crate::wire::parse_strict_json_bytes;

const PRODUCER: &str = "fortress.go-test-declarations@0.1.0";
const LIMITATIONS: [&str; 5] = [
    "DECLARATIONS_AND_DIRECT_TESTING_IMPORT_SPELLING_ONLY",
    "NO_PACKAGE_COMPILATION_OR_RUNNER_VALIDATION",
    "NO_TEST_EXECUTION_COVERAGE_OR_VERIFICATION_RELATIONSHIPS",
    "NO_BENCHMARK_FUZZ_EXAMPLE_OR_DYNAMIC_SUBTEST_DISCOVERY",
    "NONSTANDARD_TEST_FRAMEWORKS_AND_TYPE_ALIASES_NOT_RESOLVED",
];

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TestStatus {
    DeclarationsObserved,
    InvalidRequest,
    InvalidSource,
    Unsupported,
    ResourceLimit,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PackageRole {
    Production,
    InternalTest,
    ExternalTest,
    UnresolvedTestPackage,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TestFile {
    path: String,
    sha256: String,
    native_match: Option<bool>,
    disposition: Disposition,
    package_name: Option<String>,
    package_role: Option<PackageRole>,
    package_span: Option<Span>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TestKind {
    Test,
    TestMainHook,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TestDisposition {
    DirectStandardSignature,
    InvalidSignature,
    ParameterImportUnresolved,
    ParameterImportMismatch,
    ExternalBodyUnobserved,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ParameterWitness {
    qualifier: String,
    qualifier_span: Span,
    type_name_span: Span,
    import_path_span: Span,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TestDeclaration {
    name: String,
    kind: TestKind,
    disposition: TestDisposition,
    span: Span,
    signature_span: Span,
    parameter: Option<ParameterWitness>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TestResponse {
    schema_version: u16,
    producer: String,
    go_toolchain: String,
    request_sha256: String,
    context_sha256: Option<String>,
    context: Option<Context>,
    build_context: Option<GoBuildContext>,
    status: TestStatus,
    diagnostic: Option<String>,
    package_name: Option<String>,
    selection: Vec<TestFile>,
    test_declarations: Vec<TestDeclaration>,
}

/// Standalone read-only test declaration and file-selection observation.
///
/// Positive rows bind declaration syntax and an explicit testing import. They
/// do not supply compilation, runner, execution, coverage or verification facts.
#[derive(Serialize)]
pub struct GoNativeTestObservation {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    binding_sha256: String,
    response_sha256: String,
    provenance: serde_json::Value,
    observation: TestResponse,
    limitations: [&'static str; 5],
}

pub(crate) fn admit_go_tests<'a>(
    selection: ExactClosedPackage<'a>,
    pin: &'a GoCollectorPin<'a>,
    context: GoBuildContext,
) -> Result<GoBuildRequest<'a>, GoObservationError> {
    if context.test_mode != GoBuildTestMode::RequireSeparateTestContext
        || context.release_minor != 22
        || selection.go_version != "go1.22"
        || selection.target_arch != "amd64"
        || !matches!(pin.go_toolchain, "go1.22.12" | "go1.22.2")
    {
        return Err(GoObservationError::UnsupportedContext);
    }
    admit_go_build(selection, pin, context)
}

impl GoBuildRequest<'_> {
    pub(crate) fn verify_tests(
        &self,
        pin: &GoCollectorPin<'_>,
        stdout: &[u8],
    ) -> Result<GoNativeTestObservation, GoObservationError> {
        let line = self.base.verify_transport(pin, stdout)?;
        let response: TestResponse =
            parse_strict_json_bytes(line).map_err(|_| GoObservationError::InvalidResponse)?;
        if response.schema_version != 1
            || response.producer != PRODUCER
            || response.go_toolchain != pin.go_toolchain
            || response.request_sha256 != self.base.request_sha256
        {
            return Err(GoObservationError::InvalidResponse);
        }
        if response.context.is_none()
            && response.context_sha256.is_none()
            && response.build_context.is_none()
            && response.selection.is_empty()
            && response.test_declarations.is_empty()
            && response.package_name.is_none()
            && matches!(
                response.diagnostic.as_deref(),
                Some("UNADMITTED_CUSTOM_BUILD_TAG" | "TEST_DECLARATION_CONTEXT_REQUIRED")
            )
        {
            return Err(GoObservationError::UnsupportedContext);
        }
        if response.context.as_ref() != Some(&self.base.context)
            || response.context_sha256.as_deref() != Some(self.base.context_sha256.as_str())
            || response.build_context.as_ref() != Some(&self.context)
            || response.selection.len() != self.base.context.source_inventory.len()
        {
            return Err(GoObservationError::InvalidResponse);
        }
        if response.test_declarations.len() > MAX_RECORDS {
            return Err(GoObservationError::ResourceLimit);
        }
        self.verify_test_files(&response)?;
        let binding =
            serde_json_canonicalizer::to_vec(&(PRODUCER, &self.base.binding_sha256, &self.context))
                .map_err(|_| GoObservationError::WireEncoding)?;
        Ok(GoNativeTestObservation {
            schema: "urn:fortress:derived:v1:go-native-test-declarations",
            schema_version: 1,
            binding_sha256: sha256(&binding),
            response_sha256: sha256(stdout),
            provenance: self.base.provenance.clone(),
            observation: response,
            limitations: LIMITATIONS,
        })
    }

    fn verify_test_files(&self, answer: &TestResponse) -> Result<(), GoObservationError> {
        let production = answer.package_name.as_deref();
        let observed = answer.status == TestStatus::DeclarationsObserved;
        let mut selected = BTreeMap::new();
        let mut first_production = None;
        for (row, source) in answer
            .selection
            .iter()
            .zip(&self.base.context.source_inventory)
        {
            if row.path != source.path || row.sha256 != source.sha256 || !valid_disposition(row) {
                return Err(GoObservationError::InvalidResponse);
            }
            if row.disposition != Disposition::SelectedGoSource {
                if observed && row.disposition != Disposition::ExcludedByNameOrConstraint {
                    return Err(GoObservationError::InvalidResponse);
                }
                continue;
            }
            let (Some(name), Some(role), Some(span)) = (
                row.package_name.as_deref(),
                row.package_role,
                row.package_span.as_ref(),
            ) else {
                return Err(GoObservationError::InvalidResponse);
            };
            if span.path != row.path || !display_name(name) || self.base.span(span)? != name {
                return Err(GoObservationError::InvalidResponse);
            }
            let expected_role = if !row.path.ends_with("_test.go") {
                first_production.get_or_insert(name);
                if observed && Some(name) != production {
                    return Err(GoObservationError::InvalidResponse);
                }
                PackageRole::Production
            } else if Some(name) == production {
                PackageRole::InternalTest
            } else if production.is_some_and(|base| name.strip_suffix("_test") == Some(base)) {
                PackageRole::ExternalTest
            } else {
                PackageRole::UnresolvedTestPackage
            };
            if role != expected_role || observed && role == PackageRole::UnresolvedTestPackage {
                return Err(GoObservationError::InvalidResponse);
            }
            selected.insert(row.path.as_str(), role);
        }
        if production != first_production {
            return Err(GoObservationError::InvalidResponse);
        }
        if !observed {
            if !answer.test_declarations.is_empty()
                || !valid_package_diagnostic(answer.status, answer.diagnostic.as_deref())
            {
                return Err(GoObservationError::InvalidResponse);
            }
            return Ok(());
        }
        if answer.diagnostic.is_some() || production.is_none_or(|name| name == "_") {
            return Err(GoObservationError::InvalidResponse);
        }
        self.verify_declarations(&answer.test_declarations, &selected)
    }

    fn verify_declarations(
        &self,
        declarations: &[TestDeclaration],
        files: &BTreeMap<&str, PackageRole>,
    ) -> Result<(), GoObservationError> {
        let mut previous = ("", 0);
        for row in declarations {
            let head = &row.signature_span;
            if !matches!(
                files.get(row.span.path.as_str()),
                Some(PackageRole::InternalTest | PackageRole::ExternalTest)
            ) || (head.path.as_str(), head.start_byte) < previous
                || !inside(&row.span, head)
                || self.base.span(&row.span)? != row.name
                || !self.base.span(head)?.starts_with("func")
                || !valid_test_name(&row.name)
                || row.kind == TestKind::TestMainHook && row.name != "TestMain"
            {
                return Err(GoObservationError::InvalidResponse);
            }
            previous = (head.path.as_str(), head.end_byte);
            match (&row.parameter, row.disposition) {
                (Some(parameter), TestDisposition::DirectStandardSignature) => {
                    self.verify_parameter(parameter, head, row.kind)?;
                }
                (None, status) if status != TestDisposition::DirectStandardSignature => {}
                _ => return Err(GoObservationError::InvalidResponse),
            }
        }
        Ok(())
    }

    fn verify_parameter(
        &self,
        parameter: &ParameterWitness,
        head: &Span,
        kind: TestKind,
    ) -> Result<(), GoObservationError> {
        let expected = match kind {
            TestKind::Test => "T",
            TestKind::TestMainHook => "M",
        };
        if !inside(&parameter.qualifier_span, head)
            || !inside(&parameter.type_name_span, head)
            || parameter.qualifier_span.end_byte >= parameter.type_name_span.start_byte
            || parameter.import_path_span.path != head.path
            || parameter.import_path_span.end_byte >= head.start_byte
            || self.base.span(&parameter.qualifier_span)? != parameter.qualifier
            || parameter.qualifier.is_empty()
            || parameter.qualifier == "_"
            || self.base.span(&parameter.type_name_span)? != expected
            || !matches!(
                self.base.span(&parameter.import_path_span)?,
                "\"testing\"" | "`testing`"
            )
        {
            return Err(GoObservationError::InvalidResponse);
        }
        Ok(())
    }
}

fn inside(span: &Span, outer: &Span) -> bool {
    span.path == outer.path
        && outer.start_byte <= span.start_byte
        && span.start_byte < span.end_byte
        && span.end_byte <= outer.end_byte
}

fn valid_test_name(name: &str) -> bool {
    // The pinned Go loader owns Unicode category matching. Reject known ASCII
    // mismatches here without substituting Rust's broader Unicode predicate.
    display_name(name)
        && name
            .strip_prefix("Test")
            .is_some_and(|rest| !rest.as_bytes().first().is_some_and(u8::is_ascii_lowercase))
}

fn valid_disposition(row: &TestFile) -> bool {
    if row.disposition != Disposition::SelectedGoSource
        && (row.package_name.is_some() || row.package_role.is_some() || row.package_span.is_some())
    {
        return false;
    }
    match row.disposition {
        Disposition::ExcludedByNameOrConstraint => row.native_match == Some(false),
        Disposition::SelectedGoSource
        | Disposition::GoParseFailure
        | Disposition::GoAstLimit
        | Disposition::DualConstraintsUnsupported
        | Disposition::GeneratedSourceContextRequired
        | Disposition::CompilerDirectiveContextRequired => row.native_match == Some(true),
        Disposition::NativeSelectionError => row.native_match.is_some(),
        Disposition::VirtualSourceUnavailable => row.native_match.is_none(),
        _ => false,
    }
}

fn valid_package_diagnostic(status: TestStatus, code: Option<&str>) -> bool {
    matches!(
        (status, code),
        (
            TestStatus::InvalidSource,
            Some(
                "NATIVE_SELECTION_ERROR"
                    | "GO_PARSE_FAILURE"
                    | "CONFLICTING_PRODUCTION_PACKAGES"
                    | "UNRECOGNIZED_TEST_PACKAGE"
            )
        ) | (
            TestStatus::Unsupported,
            Some(
                "CGO_CONTEXT_UNSUPPORTED"
                    | "DUAL_CONSTRAINTS_UNSUPPORTED"
                    | "GENERATED_SOURCE_CONTEXT_REQUIRED"
                    | "COMPILER_DIRECTIVE_CONTEXT_REQUIRED"
                    | "VIRTUAL_SOURCE_UNAVAILABLE"
                    | "PRODUCTION_PACKAGE_UNESTABLISHED"
            )
        ) | (
            TestStatus::ResourceLimit,
            Some("GO_TEST_DECLARATION_LIMIT" | "GO_AST_LIMIT")
        )
    )
}
