//! Bound native Go build selection and its exact included and excluded inventory.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    Context, ExactClosedPackage, GoCollectorPin, GoObservationError, GoRequest, MAX_RECORDS,
    Request, Response, Status, admit_go_with, display_name, portable_ascii_path, sha256,
};
use crate::wire::parse_strict_json_bytes;

const SCHEMA: &str = "urn:fortress:derived:v2:go-native-build-observation";
const PRODUCER: &str = "fortress.go-build-selection@0.1.0";
const LIMITATIONS: [&str; 6] = [
    "HOST_MUST_ESTABLISH_PACKAGE_AND_CONTEXT_COMPLETENESS",
    "FILE_SELECTION_DOES_NOT_ESTABLISH_PACKAGE_OR_BUILD_COMPLETENESS",
    "NO_DEPENDENCIES_FOREIGN_GENERATED_OR_TEST_EXECUTION_CONTEXT",
    "BODYLESS_DECLARATIONS_DO_NOT_ESTABLISH_IMPLEMENTATION",
    "NO_RUNTIME_EFFECT_REACHABILITY_OR_EXECUTION_PROOF",
    "INTERFACE_FUNCTION_VALUE_AND_OTHER_UNSUPPORTED_DISPATCH_REMAINS_UNRESOLVED",
];

/// Explicit treatment of otherwise matching Go test files.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GoBuildTestMode {
    /// Decline a matching test file until separate test context is established.
    RequireSeparateTestContext,
    /// Select production source and retain matching test files as excluded.
    ProductionOnly,
}

/// Host-selected native Go build context. Repository defaults carry no authority.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoBuildContext {
    /// Compiler family used for the declared constraint context.
    pub compiler: String,
    /// Latest admitted Go minor release tag, including its predecessors.
    pub release_minor: u8,
    /// Whether cgo is requested. A true value is unsupported.
    pub cgo_enabled: bool,
    /// Declared handling of matching test files.
    pub test_mode: GoBuildTestMode,
    /// Exact explicitly selected custom tags. The native pin validates reserved tags.
    pub custom_tags: Vec<String>,
    /// Exact explicit architecture-feature tags.
    pub tool_tags: Vec<String>,
}

impl GoBuildContext {
    pub(super) fn admit(
        &mut self,
        selection: ExactClosedPackage<'_>,
    ) -> Result<(), GoObservationError> {
        if self.custom_tags.len() > 8 || self.tool_tags.len() > 4 {
            return Err(GoObservationError::ResourceLimit);
        }
        if self.compiler != "gc"
            || !(17..=22).contains(&self.release_minor)
            || (selection.go_version == "go1.22" && self.release_minor < 22)
            || self.cgo_enabled
            || self.custom_tags.iter().any(|tag| {
                tag.len() > 32
                    || !tag.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                    || !tag.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            })
        {
            return Err(GoObservationError::UnsupportedContext);
        }
        self.custom_tags.sort_unstable();
        self.tool_tags.sort_unstable();
        if self.custom_tags.windows(2).any(|pair| pair[0] == pair[1])
            || match selection.target_arch {
                "amd64" => {
                    self.tool_tags.is_empty()
                        || self
                            .tool_tags
                            .iter()
                            .enumerate()
                            .any(|(index, tag)| tag != &format!("amd64.v{}", index + 1))
                }
                "arm64" => !self.tool_tags.is_empty(),
                _ => true,
            }
        {
            return Err(GoObservationError::UnsupportedContext);
        }
        Ok(())
    }
}

pub(super) fn valid_source_path(path: &str, dir: &str, name: &str) -> bool {
    if let Some(rest) = name.strip_prefix('.') {
        path.len() <= 240
            && name.len() <= 96
            && name != ".go"
            && if dir.is_empty() {
                portable_ascii_path(rest)
            } else {
                portable_ascii_path(&format!("{dir}/{rest}"))
            }
    } else {
        portable_ascii_path(path)
    }
}

pub(super) fn encode_request(
    request: &Request<'_>,
    build_context: &GoBuildContext,
) -> serde_json::Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Envelope<'borrow, 'source> {
        #[serde(flatten)]
        request: &'borrow Request<'source>,
        build_context: &'borrow GoBuildContext,
    }
    serde_json::to_vec(&Envelope {
        request,
        build_context,
    })
}

pub(super) fn encode_context(
    source_context: &Context,
    build_context: &GoBuildContext,
) -> serde_json::Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Envelope<'a> {
        source_context: &'a Context,
        build_context: &'a GoBuildContext,
    }
    serde_json::to_vec(&Envelope {
        source_context,
        build_context,
    })
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum Disposition {
    UnvisitedModulePackage,
    ExcludedByNameOrConstraint,
    ProductionTestExcluded,
    SelectedGoSource,
    NativeSelectionError,
    GoParseFailure,
    GoAstLimit,
    TestContextRequired,
    DualConstraintsUnsupported,
    GeneratedSourceContextRequired,
    CompilerDirectiveContextRequired,
    CgoContextUnsupported,
    DependencyContextRequired,
    VirtualSourceUnavailable,
}

impl Disposition {
    pub(super) fn failure(self) -> Option<(Status, &'static str)> {
        Some(match self {
            Self::UnvisitedModulePackage
            | Self::SelectedGoSource
            | Self::ProductionTestExcluded
            | Self::ExcludedByNameOrConstraint => return None,
            Self::NativeSelectionError => (Status::InvalidSource, "NATIVE_SELECTION_ERROR"),
            Self::GoParseFailure => (Status::InvalidSource, "GO_PARSE_FAILURE"),
            Self::GoAstLimit => (Status::ResourceLimit, "GO_AST_LIMIT"),
            Self::TestContextRequired => (Status::Unsupported, "TEST_CONTEXT_REQUIRED"),
            Self::DualConstraintsUnsupported => {
                (Status::Unsupported, "DUAL_CONSTRAINTS_UNSUPPORTED")
            }
            Self::GeneratedSourceContextRequired => {
                (Status::Unsupported, "GENERATED_SOURCE_CONTEXT_REQUIRED")
            }
            Self::CompilerDirectiveContextRequired => {
                (Status::Unsupported, "COMPILER_DIRECTIVE_CONTEXT_REQUIRED")
            }
            Self::CgoContextUnsupported => (Status::Unsupported, "CGO_CONTEXT_UNSUPPORTED"),
            Self::DependencyContextRequired => (Status::Unsupported, "DEPENDENCY_CONTEXT_REQUIRED"),
            Self::VirtualSourceUnavailable => (Status::Unsupported, "VIRTUAL_SOURCE_UNAVAILABLE"),
        })
    }

    pub(super) fn agrees(
        self,
        native_match: Option<bool>,
        is_test: bool,
        mode: GoBuildTestMode,
    ) -> bool {
        match self {
            Self::UnvisitedModulePackage => false,
            Self::ExcludedByNameOrConstraint => native_match == Some(false),
            Self::ProductionTestExcluded => {
                is_test && native_match == Some(true) && mode == GoBuildTestMode::ProductionOnly
            }
            Self::SelectedGoSource
            | Self::GoParseFailure
            | Self::GoAstLimit
            | Self::DualConstraintsUnsupported
            | Self::GeneratedSourceContextRequired
            | Self::CompilerDirectiveContextRequired
            | Self::CgoContextUnsupported
            | Self::DependencyContextRequired => !is_test && native_match == Some(true),
            Self::NativeSelectionError => native_match.is_some(),
            Self::VirtualSourceUnavailable => native_match.is_none(),
            Self::TestContextRequired => {
                is_test
                    && native_match == Some(true)
                    && mode == GoBuildTestMode::RequireSeparateTestContext
            }
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileSelection {
    path: String,
    sha256: String,
    native_match: Option<bool>,
    disposition: Disposition,
}

/// Standalone exact native observations and the full build-selection receipt.
#[derive(Serialize)]
pub struct GoNativeBuildObservation {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    binding_sha256: String,
    response_sha256: String,
    provenance: serde_json::Value,
    build_context: GoBuildContext,
    selection: Vec<FileSelection>,
    observation: Response,
}

pub(crate) struct GoBuildRequest<'a> {
    pub(super) base: GoRequest<'a>,
    pub(super) context: GoBuildContext,
}

pub(crate) fn admit_go_build<'a>(
    selection: ExactClosedPackage<'a>,
    pin: &'a GoCollectorPin<'a>,
    mut context: GoBuildContext,
) -> Result<GoBuildRequest<'a>, GoObservationError> {
    context.admit(selection)?;
    let base = admit_go_with(selection, pin, Some(&context))?;
    Ok(GoBuildRequest { base, context })
}

impl GoBuildRequest<'_> {
    pub(crate) fn request_bytes(&self) -> &[u8] {
        self.base.request_bytes()
    }

    pub(crate) fn verify(
        &self,
        launched: &GoCollectorPin<'_>,
        stdout: &[u8],
    ) -> Result<GoNativeBuildObservation, GoObservationError> {
        let line = self.base.verify_transport(launched, stdout)?;
        let mut envelope: serde_json::Map<String, serde_json::Value> =
            parse_strict_json_bytes(line).map_err(|_| GoObservationError::InvalidResponse)?;
        let context = envelope.remove("build_context");
        let inventory: Vec<FileSelection> = envelope
            .remove("selection")
            .and_then(|value| serde_json::from_value(value).ok())
            .ok_or(GoObservationError::InvalidResponse)?;
        let answer: Response = serde_json::from_value(serde_json::Value::Object(envelope))
            .map_err(|_| GoObservationError::InvalidResponse)?;
        self.base
            .verify_header(&answer, 2, PRODUCER, &LIMITATIONS)?;
        if context.is_none() && inventory.is_empty() {
            return Err(context_refusal(&answer));
        }
        let callback_context: GoBuildContext = context
            .and_then(|value| serde_json::from_value(value).ok())
            .ok_or(GoObservationError::InvalidResponse)?;
        if callback_context != self.context
            || answer.context.as_ref() != Some(&self.base.context)
            || answer.context_sha256.as_deref() != Some(self.base.context_sha256.as_str())
            || answer.declarations.len() + answer.calls.len() > MAX_RECORDS
        {
            return Err(GoObservationError::InvalidResponse);
        }
        let selected = self.verify_inventory(&inventory)?;
        self.verify_observation(&answer, &inventory, &selected)?;
        Ok(GoNativeBuildObservation {
            schema: SCHEMA,
            schema_version: 2,
            binding_sha256: self.base.binding_sha256.clone(),
            response_sha256: sha256(stdout),
            provenance: self.base.provenance.clone(),
            build_context: callback_context,
            selection: inventory,
            observation: answer,
        })
    }

    fn verify_inventory<'b>(
        &self,
        inventory: &'b [FileSelection],
    ) -> Result<BTreeSet<&'b str>, GoObservationError> {
        if inventory.len() != self.base.context.source_inventory.len() {
            return Err(GoObservationError::InvalidResponse);
        }
        let mut selected = BTreeSet::new();
        for (entry, source) in inventory.iter().zip(&self.base.context.source_inventory) {
            if source.path != entry.path
                || source.sha256 != entry.sha256
                || !entry.disposition.agrees(
                    entry.native_match,
                    entry.path.ends_with("_test.go"),
                    self.context.test_mode,
                )
            {
                return Err(GoObservationError::InvalidResponse);
            }
            if entry.disposition == Disposition::SelectedGoSource {
                selected.insert(entry.path.as_str());
            }
        }
        Ok(selected)
    }

    fn verify_observation(
        &self,
        answer: &Response,
        inventory: &[FileSelection],
        selected: &BTreeSet<&str>,
    ) -> Result<(), GoObservationError> {
        let first_failure = inventory
            .iter()
            .find_map(|entry| entry.disposition.failure());
        if answer.status == Status::Observed {
            if first_failure.is_some()
                || selected.is_empty()
                || answer.diagnostic.is_some()
                || !answer.package_name.as_deref().is_some_and(display_name)
                || answer
                    .declarations
                    .iter()
                    .any(|decl| !selected.contains(decl.span.path.as_str()))
                || answer.calls.iter().any(|call| {
                    !selected.contains(call.span.path.as_str())
                        || call
                            .declaration
                            .as_ref()
                            .is_some_and(|span| !selected.contains(span.path.as_str()))
                })
            {
                return Err(GoObservationError::InvalidResponse);
            }
            return self.base.verify_records(answer);
        }
        if !answer.calls.is_empty()
            || !answer.declarations.is_empty()
            || answer.package_name.is_some()
        {
            return Err(GoObservationError::InvalidResponse);
        }
        let diagnostic = answer
            .diagnostic
            .as_ref()
            .ok_or(GoObservationError::InvalidResponse)?;
        if let Some((status, code)) = first_failure {
            if answer.status == status && diagnostic.code == code && diagnostic.span.is_none() {
                return Ok(());
            }
            return Err(GoObservationError::InvalidResponse);
        }
        let allowed = if selected.is_empty() {
            answer.status == Status::Unsupported && diagnostic.code == "NO_SELECTED_GO_SOURCE"
        } else {
            matches!(
                (&answer.status, diagnostic.code.as_str()),
                (Status::InvalidSource, "GO_TYPE_CHECK_REJECTED")
                    | (Status::ResourceLimit, "GO_OBSERVATION_LIMIT")
                    | (Status::Unsupported, "GO_UNRESOLVED_DECLARATION")
            )
        };
        if !allowed {
            return Err(GoObservationError::InvalidResponse);
        }
        if let Some(span) = &diagnostic.span {
            if diagnostic.code != "GO_TYPE_CHECK_REJECTED" || !selected.contains(span.path.as_str())
            {
                return Err(GoObservationError::InvalidResponse);
            }
            self.base.span(span)?;
        }
        Ok(())
    }
}

fn context_refusal(answer: &Response) -> GoObservationError {
    if !answer.declarations.is_empty()
        || !answer.calls.is_empty()
        || answer.package_name.is_some()
        || answer.context.is_some()
        || answer.context_sha256.is_some()
    {
        return GoObservationError::InvalidResponse;
    }
    let Some(diagnostic) = answer
        .diagnostic
        .as_ref()
        .filter(|diagnostic| diagnostic.span.is_none())
    else {
        return GoObservationError::InvalidResponse;
    };
    match (&answer.status, diagnostic.code.as_str()) {
        (Status::ResourceLimit, "RESPONSE_BYTE_LIMIT") => GoObservationError::ResourceLimit,
        (Status::Unsupported, "UNADMITTED_CUSTOM_BUILD_TAG") => {
            GoObservationError::UnsupportedContext
        }
        _ => GoObservationError::InvalidResponse,
    }
}
