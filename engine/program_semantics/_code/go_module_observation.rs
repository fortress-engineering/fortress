//! Exact source and typed wire admission for the closed native Go module observer.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use super::build_selection::{Disposition, valid_source_path};
use super::{
    Activation, Call, Context, Declaration, Diagnostic, ExactClosedPackage, GoBuildContext,
    GoCollectorPin, GoObservationError, GoRequest, MAX_FILE, MAX_FILES, MAX_RECORDS, MAX_SOURCE,
    MAX_WIRE, Request, RequestFile, Resolution, SourceIdentity, SourceText, Span, Status, digest,
    display_name, has_case_alias, portable_ascii_path, seal_go_request, sha256,
};
use crate::implementation_observation::{
    ImplementationObservationInput, NativeDependencyBatch, NativeDependencyContext,
    NativeDependencyEndpoint, NativeDependencyFile, NativeDependencyLanguage,
    NativeDependencyOccurrence, NativeDependencyTarget, adapt_native_dependencies,
};
use crate::wire::parse_strict_json_bytes;

#[path = "go_callable.rs"]
mod callable;

const SCHEMA: &str = "urn:fortress:derived:v3:go-native-module-observation";
const PRODUCER: &str = "fortress.go-module-observations@0.1.0";
const LIMITATIONS: [&str; 6] = [
    "HOST_MUST_ESTABLISH_COMPLETE_ORDINARY_MODULE_AND_CONTEXT",
    "ONLY_REACHABLE_PURE_GO_LIBRARY_PACKAGES_ARE_OBSERVED",
    "NO_EXTERNAL_STANDARD_LIBRARY_CGO_WORKSPACE_OR_GENERATED_CONTEXT",
    "BODYLESS_DECLARATIONS_DO_NOT_ESTABLISH_IMPLEMENTATION",
    "NO_RUNTIME_EFFECT_REACHABILITY_OR_EXECUTION_PROOF",
    "INTERFACE_FUNCTION_VALUE_AND_OTHER_UNSUPPORTED_DISPATCH_REMAINS_UNRESOLVED",
];
const MAX_PACKAGES: usize = 8;
const MAX_IMPORTS: usize = 64;
const MAX_MOD: usize = 4096;

/// Identifies a package-scope type declaration for an independent comparison.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoTypeSelector {
    /// Exact import path of the type's package.
    pub package_path: String,
    /// Type declaration name as spelled by its owning source.
    pub name: String,
}

/// Two explicitly selected native type declarations in the same package universe.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoTypeComparison {
    /// First exact type selector.
    pub left: GoTypeSelector,
    /// Second exact type selector.
    pub right: GoTypeSelector,
}

/// Independently selected module and entry package within actual source.
#[derive(Clone, Copy)]
pub struct GoModuleSelection<'a> {
    /// Exact project-relative module root, with empty string for project root.
    pub directory: &'a str,
    /// Host-selected module identity, checked against exact captured go.mod bytes.
    pub module_path: &'a str,
    /// Exact entry import path derived from the selected module root.
    pub entry_path: &'a str,
    /// Selected compile target operating system.
    pub target_os: &'a str,
    /// Selected compile target architecture.
    pub target_arch: &'a str,
    /// Optional exact comparison within the reachable package universe.
    pub comparison: Option<&'a GoTypeComparison>,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Package {
    import_path: String,
    directory: String,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ModuleIdentity {
    root_directory: String,
    path: String,
    definition: SourceIdentity,
    packages: Vec<Package>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    path: String,
    sha256: String,
    native_match: Option<bool>,
    disposition: Disposition,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Import {
    target_package: String,
    alias: String,
    span: Span,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ModuleCall {
    name: Option<String>,
    resolution: Resolution,
    activation: Activation,
    span: Span,
    declaration: Option<Span>,
    declaration_package: Option<String>,
}

impl ModuleCall {
    fn observed(&self) -> Call {
        Call {
            name: self.name.clone(),
            resolution: self.resolution.clone(),
            activation: self.activation.clone(),
            span: self.span.clone(),
            declaration: self.declaration.clone(),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Facts {
    import_path: String,
    package_name: String,
    imports: Vec<Import>,
    declarations: Vec<Declaration>,
    calls: Vec<ModuleCall>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Comparison {
    left: GoTypeSelector,
    right: GoTypeSelector,
    identical: bool,
    left_source: Span,
    right_source: Span,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    schema_version: u16,
    producer: String,
    go_toolchain: String,
    request_sha256: String,
    context_sha256: Option<String>,
    context: Option<Context>,
    build_context: Option<GoBuildContext>,
    module: Option<ModuleIdentity>,
    status: Status,
    diagnostic: Option<Diagnostic>,
    selection: Vec<Selection>,
    observed_packages: Vec<Facts>,
    type_comparison: Option<Comparison>,
    limitations: Vec<String>,
}

/// A verified native Go module observation, separate from PSM and certification.
#[derive(Serialize)]
pub struct GoNativeModuleObservation {
    #[serde(rename = "$schema")]
    schema: &'static str,
    schema_version: u16,
    binding_sha256: String,
    response_sha256: String,
    provenance: serde_json::Value,
    observation: Response,
}

pub(crate) struct GoModuleRequest<'a> {
    base: GoRequest<'a>,
    build_context: GoBuildContext,
    module: ModuleIdentity,
    comparison: Option<&'a GoTypeComparison>,
    owners: BTreeMap<&'a str, String>,
}

fn reserved(segment: &str) -> bool {
    matches!(segment, "internal" | "vendor" | "testdata" | "__fortress")
}

fn relative_directory(value: &str) -> bool {
    value.is_empty()
        || portable_ascii_path(value)
            && value.split('/').all(|component| {
                component == "_code"
                    || !reserved(component)
                        && component
                            .as_bytes()
                            .first()
                            .is_some_and(u8::is_ascii_lowercase)
                        && component
                            .bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            })
}

fn exact_module_path(value: &str) -> bool {
    if !portable_ascii_path(value) || value.split('/').any(reserved) {
        return false;
    }
    let mut parts = value.split('/');
    let host = parts.next().unwrap_or_default();
    let Some((_, top_level)) = host.rsplit_once('.') else {
        return false;
    };
    top_level.bytes().all(|c| c.is_ascii_lowercase())
        && host.split(['.', '-']).all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
        && parts.all(|segment| {
            segment
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_lowercase)
                && segment.bytes().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
                })
        })
}

fn module_definition(bytes: &[u8], expected: &str) -> Result<(), GoObservationError> {
    if bytes.len() > MAX_MOD {
        return Err(GoObservationError::ResourceLimit);
    }
    let unsupported = GoObservationError::UnsupportedContext;
    if !bytes
        .iter()
        .all(|b| matches!(*b, b'\t' | b'\n' | b'\r' | b' '..=b'~'))
    {
        return Err(unsupported);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| GoObservationError::UnsupportedContext)?;
    let lines: Vec<_> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let [module, version] = lines.as_slice() else {
        return Err(unsupported);
    };
    if text.replace("\r\n", "\n").contains('\r')
        || !module.split_ascii_whitespace().eq(["module", expected])
        || !version.split_ascii_whitespace().eq(["go", "1.22"])
    {
        return Err(unsupported);
    }
    Ok(())
}

fn validate_setup(
    closed: ExactClosedPackage<'_>,
    selection: GoModuleSelection<'_>,
    pin: &GoCollectorPin<'_>,
    context: &mut GoBuildContext,
) -> Result<(), GoObservationError> {
    if ![
        closed.source_fingerprint,
        closed.authority_digest,
        pin.executable_sha256,
        pin.supervisor_context_sha256,
    ]
    .into_iter()
    .all(digest)
        || !matches!(pin.go_toolchain, "go1.22.2" | "go1.22.12")
    {
        return Err(GoObservationError::InvalidTrustedBinding);
    }
    if !closed.actual
        || !exact_module_path(selection.module_path)
        || !portable_ascii_path(selection.entry_path)
        || (!selection.directory.is_empty()
            && (!portable_ascii_path(selection.directory)
                || selection.directory.split('/').any(reserved)))
        || !matches!(selection.target_os, "windows" | "linux")
        || selection.target_arch != "amd64"
        || selection.comparison.is_some_and(|pair| {
            [&pair.left, &pair.right].into_iter().any(|part| {
                !portable_ascii_path(&part.package_path)
                    || part.name.len() > 96
                    || !part
                        .name
                        .as_bytes()
                        .first()
                        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
                    || !part
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
        })
    {
        return Err(GoObservationError::UnsupportedContext);
    }
    context.admit(closed)
}

fn marker(name: &str) -> bool {
    [
        "go.mod",
        "go.work",
        "go.sum",
        "go.work.sum",
        "godebug",
        ".godebug",
    ]
    .iter()
    .any(|marker| name.eq_ignore_ascii_case(marker))
}

struct Inventory<'a> {
    files: BTreeMap<&'a str, SourceText<'a>>,
    owners: BTreeMap<&'a str, String>,
    wire: Vec<RequestFile<'a>>,
    identities: Vec<SourceIdentity>,
    packages: BTreeMap<String, String>,
}

impl<'a> Inventory<'a> {
    fn capture(
        closed: ExactClosedPackage<'a>,
        selection: GoModuleSelection<'_>,
        prefix: &str,
        definition: &str,
    ) -> Result<Self, GoObservationError> {
        let mut inventory = Self {
            files: BTreeMap::new(),
            owners: BTreeMap::new(),
            wire: Vec::new(),
            identities: Vec::new(),
            packages: BTreeMap::new(),
        };
        let mut total = 0;
        let mut folded = BTreeSet::new();
        for (path, bytes) in closed.source.files() {
            // The original project selects these canonical Module contracts as
            // authority in an inert Go directory. Exact source still binds them.
            if path == definition
                || path.starts_with("__fortress/")
                || closed.logical_contracts.contains(path)
            {
                continue;
            }
            let (dir, file) = path.rsplit_once('/').unwrap_or(("", path));
            if has_case_alias(path, selection.directory)
                || path == selection.directory
                || marker(file)
                    && (dir.is_empty()
                        || selection
                            .directory
                            .strip_prefix(dir)
                            .is_some_and(|rest| rest.starts_with('/')))
            {
                return Err(GoObservationError::UnsupportedContext);
            }
            let Some(relative) = path.strip_prefix(prefix) else {
                continue;
            };
            let (relative_dir, filename) = relative.rsplit_once('/').unwrap_or(("", relative));
            if !relative_directory(relative_dir) {
                return Err(GoObservationError::UnsupportedContext);
            }
            if matches!(
                filename,
                "README.md" | "LICENSE" | "LICENSE.txt" | "LICENSE.md" | "contract.json"
            ) {
                continue;
            }
            if !valid_source_path(path, dir, filename)
                || Path::new(filename).extension() != Some(OsStr::new("go"))
                || !folded.insert(path.to_ascii_lowercase())
            {
                return Err(GoObservationError::UnsupportedContext);
            }
            total += bytes.len();
            if bytes.len() > MAX_FILE || total > MAX_SOURCE || inventory.files.len() >= MAX_FILES {
                return Err(GoObservationError::ResourceLimit);
            }
            let package = if relative_dir.is_empty() {
                selection.module_path.to_owned()
            } else {
                format!("{}/{relative_dir}", selection.module_path)
            };
            if !portable_ascii_path(&package) {
                return Err(GoObservationError::UnsupportedContext);
            }
            inventory
                .packages
                .entry(package.clone())
                .or_insert_with(|| {
                    if relative_dir.is_empty() {
                        ".".into()
                    } else {
                        relative_dir.into()
                    }
                });
            if inventory.packages.len() > MAX_PACKAGES {
                return Err(GoObservationError::ResourceLimit);
            }
            let sha = sha256(bytes);
            inventory
                .files
                .insert(path.as_str(), SourceText::new(bytes)?);
            inventory.owners.insert(path.as_str(), package);
            inventory.identities.push(SourceIdentity {
                path: path.clone(),
                sha256: sha.clone(),
            });
            inventory.wire.push(RequestFile {
                path,
                sha256: sha,
                source_base64: STANDARD.encode(bytes),
            });
        }
        if !inventory.packages.contains_key(selection.entry_path) {
            return Err(GoObservationError::UnsupportedContext);
        }
        Ok(inventory)
    }
}

#[derive(Serialize)]
struct WireModule<'a> {
    root_directory: &'a str,
    path: &'a str,
    definition: RequestFile<'a>,
    packages: &'a [Package],
}

#[derive(Serialize)]
struct WireRequest<'a, 'source> {
    #[serde(flatten)]
    request: Request<'source>,
    build_context: &'a GoBuildContext,
    module: WireModule<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    type_comparison: Option<&'a GoTypeComparison>,
}

#[derive(Serialize)]
struct WireContext<'a> {
    source_context: &'a Context,
    build_context: &'a GoBuildContext,
    module: &'a ModuleIdentity,
}

pub(crate) fn admit_go_module<'a>(
    closed: ExactClosedPackage<'a>,
    selected: GoModuleSelection<'a>,
    pin: &'a GoCollectorPin<'a>,
    mut build_context: GoBuildContext,
) -> Result<GoModuleRequest<'a>, GoObservationError> {
    validate_setup(closed, selected, pin, &mut build_context)?;
    let prefix = if selected.directory.is_empty() {
        String::new()
    } else {
        format!("{}/", selected.directory)
    };
    let path = format!("{prefix}go.mod");
    let definition = closed
        .source
        .bytes(&path)
        .ok_or(GoObservationError::UnsupportedContext)?;
    module_definition(definition, selected.module_path)?;
    let inventory = Inventory::capture(closed, selected, &prefix, &path)?;
    let module = ModuleIdentity {
        root_directory: if selected.directory.is_empty() {
            ".".into()
        } else {
            selected.directory.into()
        },
        path: selected.module_path.into(),
        definition: SourceIdentity {
            path: path.clone(),
            sha256: sha256(definition),
        },
        packages: inventory
            .packages
            .into_iter()
            .map(|(import_path, directory)| Package {
                import_path,
                directory,
            })
            .collect(),
    };
    let context = Context {
        package_path: selected.entry_path.into(),
        go_version: "go1.22".into(),
        target_os: selected.target_os.into(),
        target_arch: selected.target_arch.into(),
        source_inventory: inventory.identities,
    };
    let wire = serde_json::to_vec(&WireRequest {
        request: Request {
            schema_version: 3,
            package_path: selected.entry_path,
            go_version: "go1.22",
            target_os: selected.target_os,
            target_arch: selected.target_arch,
            files: inventory.wire,
        },
        build_context: &build_context,
        module: WireModule {
            root_directory: &module.root_directory,
            path: &module.path,
            definition: RequestFile {
                path: &path,
                sha256: module.definition.sha256.clone(),
                source_base64: STANDARD.encode(definition),
            },
            packages: &module.packages,
        },
        type_comparison: selected.comparison,
    })
    .map_err(|_| GoObservationError::WireEncoding)?;
    if wire.len() > MAX_WIRE {
        return Err(GoObservationError::ResourceLimit);
    }
    let context_bytes = serde_json::to_vec(&WireContext {
        source_context: &context,
        build_context: &build_context,
        module: &module,
    })
    .map_err(|_| GoObservationError::WireEncoding)?;
    let base = seal_go_request(
        closed,
        pin,
        inventory.files,
        context,
        (wire, context_bytes),
        "fortress-go-module-observation-input-v3",
    )?;
    Ok(GoModuleRequest {
        base,
        build_context,
        module,
        comparison: selected.comparison,
        owners: inventory.owners,
    })
}

impl GoModuleRequest<'_> {
    pub(crate) fn dependency_paths(&self) -> impl Iterator<Item = &str> {
        self.base
            .context
            .source_inventory
            .iter()
            .map(|file| file.path.as_str())
    }

    pub(crate) fn dependency_context(&self) -> &str {
        &self.base.binding_sha256
    }

    pub(crate) fn project_dependencies(
        &self,
        input: &ImplementationObservationInput,
        expected: NativeDependencyContext<'_>,
        receipt: &GoNativeModuleObservation,
    ) -> Result<Option<serde_json::Value>, GoObservationError> {
        let response = &receipt.observation;
        if response.status != Status::Observed {
            return Ok(None);
        }
        let context = NativeDependencyContext {
            snapshot_fingerprint: receipt.provenance["source_fingerprint"]
                .as_str()
                .ok_or(GoObservationError::InvalidResponse)?,
            source_view_sha256: receipt.provenance["source_view_sha256"]
                .as_str()
                .ok_or(GoObservationError::InvalidResponse)?,
            authority_sha256: receipt.provenance["authority_sha256"]
                .as_str()
                .ok_or(GoObservationError::InvalidResponse)?,
            context_sha256: &receipt.binding_sha256,
        };
        let mut selected = BTreeMap::new();
        let mut packages = BTreeMap::<&str, Vec<NativeDependencyFile<'_>>>::new();
        for file in response
            .selection
            .iter()
            .filter(|file| file.disposition == Disposition::SelectedGoSource)
        {
            let identity = NativeDependencyFile {
                path: &file.path,
                sha256: &file.sha256,
            };
            let package = self
                .owners
                .get(file.path.as_str())
                .ok_or(GoObservationError::InvalidResponse)?;
            packages.entry(package).or_default().push(identity);
            selected.insert(file.path.as_str(), identity);
        }
        let mut endpoints = Vec::new();
        for import in response
            .observed_packages
            .iter()
            .flat_map(|package| &package.imports)
        {
            let file = *selected
                .get(import.span.path.as_str())
                .ok_or(GoObservationError::InvalidResponse)?;
            let target = packages
                .get(import.target_package.as_str())
                .ok_or(GoObservationError::InvalidResponse)?;
            endpoints.push(NativeDependencyEndpoint {
                occurrence: NativeDependencyOccurrence {
                    file,
                    start_byte: import.span.start_byte,
                    end_byte: import.span.end_byte,
                    reference: &import.target_package,
                },
                target: NativeDependencyTarget::GoClosedPackage(target),
            });
        }
        let admitted = NativeDependencyBatch {
            language: NativeDependencyLanguage::Go,
            context,
            observation_sha256: &receipt.response_sha256,
            endpoints: &endpoints,
        };
        let report =
            adapt_native_dependencies(input, expected, &admitted).map_err(|error| match error {
                crate::implementation_observation::NativeDependencyAdapterError::ResourceLimit => {
                    GoObservationError::ResourceLimit
                }
                _ => GoObservationError::InvalidResponse,
            })?;
        serde_json::to_value(report)
            .map(Some)
            .map_err(|_| GoObservationError::WireEncoding)
    }

    pub(crate) fn request_bytes(&self) -> &[u8] {
        self.base.request_bytes()
    }

    pub(crate) fn verify(
        &self,
        launched: &GoCollectorPin<'_>,
        stdout: &[u8],
    ) -> Result<GoNativeModuleObservation, GoObservationError> {
        let line = self.base.verify_transport(launched, stdout)?;
        let answer: Response =
            parse_strict_json_bytes(line).map_err(|_| GoObservationError::InvalidResponse)?;
        if answer.schema_version != 3
            || answer.producer != PRODUCER
            || answer.go_toolchain != self.base.pin.go_toolchain
            || answer.request_sha256 != self.base.request_sha256
            || !answer
                .limitations
                .iter()
                .map(String::as_str)
                .eq(LIMITATIONS)
        {
            return Err(GoObservationError::InvalidResponse);
        }
        if answer.context.is_none()
            && answer.context_sha256.is_none()
            && answer.build_context.is_none()
            && answer.module.is_none()
            && answer.selection.is_empty()
            && answer.observed_packages.is_empty()
            && answer.type_comparison.is_none()
        {
            if answer.status == Status::ResourceLimit
                && answer
                    .diagnostic
                    .as_ref()
                    .is_some_and(|d| d.code == "RESPONSE_BYTE_LIMIT" && d.span.is_none())
            {
                return Err(GoObservationError::ResourceLimit);
            }
            if answer.status == Status::Unsupported
                && answer
                    .diagnostic
                    .as_ref()
                    .is_some_and(|d| d.code == "UNADMITTED_CUSTOM_BUILD_TAG" && d.span.is_none())
            {
                return Err(GoObservationError::UnsupportedContext);
            }
        }
        if answer.context.as_ref() != Some(&self.base.context)
            || answer.context_sha256.as_deref() != Some(self.base.context_sha256.as_str())
            || answer.build_context.as_ref() != Some(&self.build_context)
            || answer.module.as_ref() != Some(&self.module)
            || answer.status == Status::InvalidRequest
        {
            return Err(GoObservationError::InvalidResponse);
        }
        let selected = self.verify_selection(&answer.selection)?;
        if answer.status == Status::Observed {
            self.verify_facts(&answer, &selected)?;
        } else {
            self.verify_refusal(&answer, &selected)?;
        }
        Ok(GoNativeModuleObservation {
            schema: SCHEMA,
            schema_version: 3,
            binding_sha256: self.base.binding_sha256.clone(),
            response_sha256: sha256(stdout),
            provenance: self.base.provenance.clone(),
            observation: answer,
        })
    }

    fn verify_selection<'a>(
        &self,
        inventory: &'a [Selection],
    ) -> Result<BTreeSet<&'a str>, GoObservationError> {
        if inventory.len() != self.base.context.source_inventory.len() {
            return Err(GoObservationError::InvalidResponse);
        }
        let mut selected = BTreeSet::new();
        for (entry, admitted) in inventory.iter().zip(&self.base.context.source_inventory) {
            if matches!(
                entry.disposition,
                Disposition::DependencyContextRequired | Disposition::CgoContextUnsupported
            ) {
                return Err(GoObservationError::InvalidResponse);
            }
            let legal = if entry.disposition == Disposition::UnvisitedModulePackage {
                entry.native_match.is_none()
            } else {
                entry.disposition.agrees(
                    entry.native_match,
                    entry.path.ends_with("_test.go"),
                    self.build_context.test_mode,
                )
            };
            if !legal || admitted.path != entry.path || admitted.sha256 != entry.sha256 {
                return Err(GoObservationError::InvalidResponse);
            }
            if entry.disposition == Disposition::SelectedGoSource {
                selected.insert(entry.path.as_str());
            }
        }
        Ok(selected)
    }

    fn verify_facts(
        &self,
        answer: &Response,
        selected: &BTreeSet<&str>,
    ) -> Result<(), GoObservationError> {
        let packages = &answer.observed_packages;
        let entry_path = self.base.context.package_path.as_str();
        if answer.diagnostic.is_some()
            || packages.len() > self.module.packages.len()
            || !packages
                .windows(2)
                .all(|pair| pair[0].import_path < pair[1].import_path)
            || answer
                .selection
                .iter()
                .any(|row| row.disposition.failure().is_some())
            || packages
                .iter()
                .map(|p| p.calls.len() + p.declarations.len())
                .sum::<usize>()
                > MAX_RECORDS
            || packages.iter().map(|p| p.imports.len()).sum::<usize>() > MAX_IMPORTS
        {
            return Err(GoObservationError::InvalidResponse);
        }
        let observed: BTreeMap<_, _> = packages
            .iter()
            .map(|p| (p.import_path.as_str(), p))
            .collect();
        let selected_packages: BTreeSet<_> = selected
            .iter()
            .map(|path| self.owners[*path].as_str())
            .collect();
        if !observed.keys().copied().eq(selected_packages)
            || !observed.contains_key(entry_path)
            || answer.selection.iter().any(|row| {
                observed.contains_key(self.owners[row.path.as_str()].as_str())
                    == (row.disposition == Disposition::UnvisitedModulePackage)
            })
        {
            return Err(GoObservationError::InvalidResponse);
        }
        for package in packages {
            self.verify_package(package, &observed, selected)?;
        }
        let mut reachable = BTreeSet::new();
        if !walk_package_graph(entry_path, &observed, &mut BTreeSet::new(), &mut reachable)
            || reachable.len() != observed.len()
        {
            return Err(GoObservationError::InvalidResponse);
        }
        let calls: Vec<_> = packages
            .iter()
            .flat_map(|p| p.calls.iter().map(ModuleCall::observed))
            .collect();
        self.base
            .verify_record_lists(packages.iter().flat_map(|p| &p.declarations), &calls)?;
        self.verify_comparison(answer.type_comparison.as_ref(), selected)
    }

    fn verify_package(
        &self,
        package: &Facts,
        observed: &BTreeMap<&str, &Facts>,
        selected: &BTreeSet<&str>,
    ) -> Result<(), GoObservationError> {
        let owns = |span: &Span| {
            selected.contains(span.path.as_str())
                && self.owners[span.path.as_str()] == package.import_path
        };
        if !display_name(&package.package_name)
            || package.package_name == "main"
            || package.declarations.iter().any(|d| !owns(&d.span))
            || package.calls.iter().any(|c| {
                !owns(&c.span)
                    || match (&c.declaration, &c.declaration_package) {
                        (Some(site), Some(owner)) => {
                            !selected.contains(site.path.as_str())
                                || self.owners[site.path.as_str()] != *owner
                        }
                        (None, None) => false,
                        _ => true,
                    }
            })
        {
            return Err(GoObservationError::InvalidResponse);
        }
        let mut sites = BTreeSet::new();
        for row in &package.imports {
            let text = self.base.span(&row.span)?;
            let lexical = text
                .strip_prefix('"')
                .and_then(|raw| raw.strip_suffix('"'))
                .or_else(|| {
                    text.strip_prefix(char::from(96))
                        .and_then(|raw| raw.strip_suffix(char::from(96)))
                });
            if !owns(&row.span)
                || !sites.insert(&row.span)
                || !observed.contains_key(row.target_package.as_str())
                || row.target_package == package.import_path
                || lexical != Some(row.target_package.as_str())
                || !(row.alias == "." || display_name(&row.alias))
            {
                return Err(GoObservationError::InvalidResponse);
            }
        }
        Ok(())
    }

    fn verify_comparison(
        &self,
        result: Option<&Comparison>,
        selected: &BTreeSet<&str>,
    ) -> Result<(), GoObservationError> {
        match (self.comparison, result) {
            (None, None) => Ok(()),
            (Some(request), Some(row))
                if (&request.left, &request.right) == (&row.left, &row.right) =>
            {
                for (selector, source) in [
                    (&row.left, &row.left_source),
                    (&row.right, &row.right_source),
                ] {
                    if !selected.contains(source.path.as_str())
                        || self.owners[source.path.as_str()] != selector.package_path
                        || self.base.span(source)? != selector.name
                    {
                        return Err(GoObservationError::InvalidResponse);
                    }
                }
                Ok(())
            }
            _ => Err(GoObservationError::InvalidResponse),
        }
    }

    fn verify_refusal(
        &self,
        answer: &Response,
        selected: &BTreeSet<&str>,
    ) -> Result<(), GoObservationError> {
        let diag = answer
            .diagnostic
            .as_ref()
            .ok_or(GoObservationError::InvalidResponse)?;
        if !answer.observed_packages.is_empty() || answer.type_comparison.is_some() {
            return Err(GoObservationError::InvalidResponse);
        }
        let mut file_failures = answer
            .selection
            .iter()
            .filter_map(|row| row.disposition.failure());
        if let Some(first) = file_failures.next() {
            return if file_failures.next().is_none()
                && first.0 == answer.status
                && first.1 == diag.code
                && diag.span.is_none()
            {
                Ok(())
            } else {
                Err(GoObservationError::InvalidResponse)
            };
        }
        match (&answer.status, diag.code.as_str()) {
            (Status::InvalidSource, "TYPE_CHECK_REJECTED" | "INVALID_GO_IMPORT")
            | (
                Status::Unsupported,
                "CGO_CONTEXT_UNSUPPORTED"
                | "RELATIVE_IMPORT_UNSUPPORTED"
                | "EXTERNAL_IMPORT_UNSUPPORTED"
                | "PACKAGE_DIRECTORY_CONTEXT_UNSUPPORTED"
                | "MISSING_LOCAL_PACKAGE",
            ) => {
                if let Some(span) = &diag.span {
                    if !selected.contains(span.path.as_str()) {
                        return Err(GoObservationError::InvalidResponse);
                    }
                    self.base.span(span)?;
                }
            }
            (Status::Unsupported, "TYPE_IDENTITY_UNAVAILABLE")
                if self.comparison.is_some() && diag.span.is_none() => {}
            (Status::InvalidSource, "CYCLIC_LOCAL_IMPORT")
            | (
                Status::Unsupported,
                "MAIN_PACKAGE_UNSUPPORTED"
                | "NO_TARGET_PACKAGE_SOURCE"
                | "GO_UNRESOLVED_DECLARATION",
            )
            | (Status::ResourceLimit, "MODULE_IMPORT_COUNT_LIMIT" | "GO_OBSERVATION_LIMIT")
                if diag.span.is_none() => {}
            _ => return Err(GoObservationError::InvalidResponse),
        }
        Ok(())
    }
}

fn walk_package_graph<'a>(
    package: &'a str,
    observed: &BTreeMap<&'a str, &'a Facts>,
    active: &mut BTreeSet<&'a str>,
    reached: &mut BTreeSet<&'a str>,
) -> bool {
    if reached.contains(package) {
        return true;
    }
    if !active.insert(package) {
        return false;
    }
    let valid = observed[package]
        .imports
        .iter()
        .all(|row| walk_package_graph(&row.target_package, observed, active, reached));
    active.remove(package);
    reached.insert(package);
    valid
}
