//! Rust-native structural observations for the registered Source Profile.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Attribute, ImplItem, Item, TraitItem, Visibility};

use crate::implementation_observation::{CargoAnalysisTerritoryObservation, CargoSourceRole};

use super::{
    RUST_SOURCE_PROFILE_ID, RegionCoverage, SemanticRegion, SourceArchetypeObservation,
    SourceArtifactInput, SourceObservation, SourceProfileFact,
};

const ADAPTER: &str = "fortress-core/rust-source-profile-v1";

/// Rust profile adapter failure for source bytes that cannot be observed truthfully.
#[derive(Debug)]
pub enum RustProfileError {
    /// One Rust artifact was not UTF-8.
    NonUtf8(Box<str>),
    /// One Rust artifact failed the canonical `syn` parser.
    Parse {
        /// Repository-relative source path.
        path: Box<str>,
        /// Parser diagnostic retained as evidence, not identity.
        detail: Box<str>,
    },
}

impl Display for RustProfileError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUtf8(path) => write!(formatter, "Rust source `{path}` is not UTF-8"),
            Self::Parse { path, detail } => {
                write!(formatter, "Rust source `{path}` cannot be parsed: {detail}")
            }
        }
    }
}

impl Error for RustProfileError {}

/// Complete deterministic Rust profile projection over observed source artifacts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RustProfileProjection {
    archetypes: Vec<SourceArchetypeObservation>,
    observations: Vec<SourceObservation>,
    facts: BTreeMap<String, Vec<SourceProfileFact>>,
}

impl RustProfileProjection {
    /// Returns mechanically established Rust file-role observations.
    #[must_use]
    pub fn archetypes(&self) -> &[SourceArchetypeObservation] {
        &self.archetypes
    }

    /// Returns universal regions projected from Rust syntax.
    #[must_use]
    pub fn observations(&self) -> &[SourceObservation] {
        &self.observations
    }

    /// Returns Rust-native facts grouped by repository-relative source path.
    #[must_use]
    pub const fn facts(&self) -> &BTreeMap<String, Vec<SourceProfileFact>> {
        &self.facts
    }
}

/// Observes Rust file roles and top-level structure using existing snapshot bytes,
/// Cargo target facts, and the canonical `syn` dependency.
///
/// This adapter does not perform name resolution, expansion, type checking, or
/// call resolution. Unsupported expansion remains visible as a profile fact.
///
/// # Errors
///
/// Returns a typed error when a Rust artifact is not UTF-8 or cannot be parsed.
pub fn observe_rust_source_profile(
    files: &BTreeMap<String, Vec<u8>>,
    artifacts: &[SourceArtifactInput],
    cargo: &[CargoAnalysisTerritoryObservation],
) -> Result<RustProfileProjection, RustProfileError> {
    let mut roles = BTreeMap::<&str, BTreeSet<CargoSourceRole>>::new();
    for territory in cargo {
        for target in territory.targets() {
            roles
                .entry(target.path())
                .or_default()
                .insert(target.role());
        }
    }
    let mut projection = RustProfileProjection::default();
    for artifact in artifacts.iter().filter(|artifact| {
        Path::new(&artifact.path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
    }) {
        let path = artifact.path.as_str();
        let bytes = files.get(path).map_or(&[][..], Vec::as_slice);
        let source = std::str::from_utf8(bytes)
            .map_err(|_| RustProfileError::NonUtf8(path.to_owned().into()))?;
        let syntax = syn::parse_file(source).map_err(|error| RustProfileError::Parse {
            path: path.to_owned().into(),
            detail: error.to_string().into(),
        })?;
        let candidates = archetype_candidates(path, roles.get(path));
        projection.archetypes.push(SourceArchetypeObservation::new(
            path,
            RUST_SOURCE_PROFILE_ID,
            candidates.clone(),
            ADAPTER,
            format!("cargo-source-role:{}", candidates.join("|")),
        ));
        let mut facts = Vec::new();
        for attribute in &syntax.attrs {
            push_attribute(&mut facts, attribute, "FILE_ATTRIBUTE");
        }
        for item in &syntax.items {
            observe_item(item, &mut facts);
        }
        let mut macro_visitor = MacroVisitor { facts: &mut facts };
        macro_visitor.visit_file(&syntax);
        complete_expected_facts(&mut facts);
        facts.sort_by(|left, right| {
            left.start_line
                .unwrap_or(u32::MAX)
                .cmp(&right.start_line.unwrap_or(u32::MAX))
                .then_with(|| left.source_reference.cmp(&right.source_reference))
        });
        facts.dedup();
        for fact in &facts {
            projection.observations.extend(regions_for_fact(path, fact));
        }
        projection.facts.insert(path.to_owned(), facts);
    }
    projection.archetypes.sort();
    projection.archetypes.dedup();
    projection.observations.sort();
    projection.observations.dedup();
    Ok(projection)
}

fn complete_expected_facts(facts: &mut Vec<SourceProfileFact>) {
    for kind in [
        "MODULE_DECLARATION",
        "USE_DECLARATION",
        "CONSTANT_DECLARATION",
        "STATIC_DECLARATION",
        "STRUCT_DECLARATION",
        "ENUM_DECLARATION",
        "TRAIT_DECLARATION",
        "INHERENT_IMPL",
        "TRAIT_IMPL",
        "FUNCTION_IMPLEMENTATION",
        "TEST_FUNCTION",
        "MACRO_DEFINITION",
        "MACRO_INVOCATION",
        "FAILURE_BEARING_SURFACE",
        "DOC_ATTRIBUTE",
    ] {
        if !facts.iter().any(|fact| fact.kind == kind) {
            facts.push(SourceProfileFact::new(
                RUST_SOURCE_PROFILE_ID,
                kind,
                None,
                None,
                RegionCoverage::Absent,
                format!("rust:{kind}:ABSENT"),
                None,
            ));
        }
    }
    if !facts
        .iter()
        .any(|fact| fact.kind == "MACRO_INVOCATION" && fact.coverage == RegionCoverage::Observed)
    {
        facts.push(SourceProfileFact::new(
            RUST_SOURCE_PROFILE_ID,
            "MACRO_EXPANSION",
            None,
            None,
            RegionCoverage::NotApplicable,
            "rust:MACRO_EXPANSION:NOT_APPLICABLE",
            None,
        ));
    }
    if !facts.iter().any(|fact| {
        fact.visibility
            .as_deref()
            .is_some_and(|value| value != "PRIVATE")
            && fact.coverage == RegionCoverage::Observed
    }) {
        facts.push(SourceProfileFact::new(
            RUST_SOURCE_PROFILE_ID,
            "PUBLIC_SURFACE",
            None,
            None,
            RegionCoverage::Absent,
            "rust:PUBLIC_SURFACE:ABSENT",
            None,
        ));
    }
}

fn archetype_candidates(
    path: &str,
    cargo_roles: Option<&BTreeSet<CargoSourceRole>>,
) -> Vec<String> {
    let mut candidates = cargo_roles
        .into_iter()
        .flatten()
        .map(|role| match role {
            CargoSourceRole::LibraryCrateRoot => "RUST_CRATE_ROOT",
            CargoSourceRole::ProcMacroCrateRoot => "RUST_PROC_MACRO_CRATE_ROOT",
            CargoSourceRole::BinaryTargetRoot
                if path.ends_with("/main.rs") && !path.contains("/src/bin/") =>
            {
                "RUST_CRATE_ROOT"
            }
            CargoSourceRole::BinaryTargetRoot => "RUST_BINARY_TARGET_ROOT",
            CargoSourceRole::BuildScript => "RUST_BUILD_SCRIPT",
            CargoSourceRole::IntegrationTest => "RUST_INTEGRATION_TEST",
            CargoSourceRole::Benchmark => "RUST_BENCHMARK",
            CargoSourceRole::Example => "RUST_EXAMPLE",
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        candidates.push(
            if path.ends_with("/mod.rs") || path == "mod.rs" {
                "RUST_MOD_MODULE"
            } else if Path::new(path)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
            {
                "RUST_MODULE"
            } else {
                "RUST_OTHER_UNKNOWN"
            }
            .into(),
        );
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

#[allow(clippy::too_many_lines)]
fn observe_item(item: &Item, facts: &mut Vec<SourceProfileFact>) {
    match item {
        Item::Use(value) => push_fact(
            facts,
            "USE_DECLARATION",
            None,
            Some(visibility(&value.vis)),
            RegionCoverage::Observed,
            value.span(),
        ),
        Item::ExternCrate(value) => push_fact(
            facts,
            "EXTERN_CRATE",
            Some(value.ident.to_string()),
            Some(visibility(&value.vis)),
            RegionCoverage::Observed,
            value.span(),
        ),
        Item::Mod(value) => {
            push_named(
                facts,
                "MODULE_DECLARATION",
                &value.ident,
                &value.vis,
                value.span(),
            );
            if let Some((_, items)) = &value.content {
                for item in items {
                    observe_item(item, facts);
                }
            }
        }
        Item::Const(value) => push_named(
            facts,
            "CONSTANT_DECLARATION",
            &value.ident,
            &value.vis,
            value.span(),
        ),
        Item::Static(value) => push_named(
            facts,
            "STATIC_DECLARATION",
            &value.ident,
            &value.vis,
            value.span(),
        ),
        Item::Struct(value) => push_named(
            facts,
            "STRUCT_DECLARATION",
            &value.ident,
            &value.vis,
            value.span(),
        ),
        Item::Enum(value) => push_named(
            facts,
            "ENUM_DECLARATION",
            &value.ident,
            &value.vis,
            value.span(),
        ),
        Item::Union(value) => push_named(
            facts,
            "UNION_DECLARATION",
            &value.ident,
            &value.vis,
            value.span(),
        ),
        Item::Type(value) => {
            push_named(facts, "TYPE_ALIAS", &value.ident, &value.vis, value.span());
        }
        Item::Trait(value) => {
            push_named(
                facts,
                "TRAIT_DECLARATION",
                &value.ident,
                &value.vis,
                value.span(),
            );
            for item in &value.items {
                if let TraitItem::Fn(function) = item {
                    push_fact(
                        facts,
                        "TRAIT_METHOD_DECLARATION",
                        Some(function.sig.ident.to_string()),
                        None,
                        RegionCoverage::Observed,
                        function.span(),
                    );
                }
            }
        }
        Item::Impl(value) => {
            push_fact(
                facts,
                if value.trait_.is_some() {
                    "TRAIT_IMPL"
                } else {
                    "INHERENT_IMPL"
                },
                None,
                None,
                RegionCoverage::Observed,
                value.span(),
            );
            for item in &value.items {
                if let ImplItem::Fn(function) = item {
                    push_fact(
                        facts,
                        "METHOD_IMPLEMENTATION",
                        Some(function.sig.ident.to_string()),
                        Some(visibility(&function.vis)),
                        RegionCoverage::Observed,
                        function.span(),
                    );
                    observe_signature(&function.sig, facts);
                }
            }
        }
        Item::Fn(value) => {
            push_named(
                facts,
                if value
                    .attrs
                    .iter()
                    .any(|attribute| attribute.path().is_ident("test"))
                {
                    "TEST_FUNCTION"
                } else {
                    "FUNCTION_IMPLEMENTATION"
                },
                &value.sig.ident,
                &value.vis,
                value.span(),
            );
            observe_signature(&value.sig, facts);
        }
        Item::Macro(value) => {
            let definition = value.ident.is_some();
            push_fact(
                facts,
                if definition {
                    "MACRO_DEFINITION"
                } else {
                    "MACRO_INVOCATION"
                },
                value.ident.as_ref().map(ToString::to_string),
                None,
                RegionCoverage::Observed,
                value.span(),
            );
            if !definition {
                push_fact(
                    facts,
                    "MACRO_EXPANSION",
                    None,
                    None,
                    RegionCoverage::Unsupported,
                    value.span(),
                );
            }
        }
        Item::ForeignMod(value) => push_fact(
            facts,
            "FOREIGN_MODULE",
            None,
            None,
            RegionCoverage::Observed,
            value.span(),
        ),
        Item::Verbatim(tokens) => push_fact(
            facts,
            "UNSUPPORTED_SYNTAX",
            None,
            None,
            RegionCoverage::Unsupported,
            tokens.span(),
        ),
        _ => {}
    }
    for attribute in item_attrs(item) {
        push_attribute(facts, attribute, "ITEM_ATTRIBUTE");
    }
}

struct MacroVisitor<'a> {
    facts: &'a mut Vec<SourceProfileFact>,
}

impl<'ast> Visit<'ast> for MacroVisitor<'_> {
    fn visit_expr_macro(&mut self, expression: &'ast syn::ExprMacro) {
        push_macro_invocation(self.facts, expression.span());
        visit::visit_expr_macro(self, expression);
    }

    fn visit_stmt_macro(&mut self, statement: &'ast syn::StmtMacro) {
        push_macro_invocation(self.facts, statement.span());
        visit::visit_stmt_macro(self, statement);
    }
}

fn push_macro_invocation(facts: &mut Vec<SourceProfileFact>, span: proc_macro2::Span) {
    push_fact(
        facts,
        "MACRO_INVOCATION",
        None,
        None,
        RegionCoverage::Observed,
        span,
    );
    push_fact(
        facts,
        "MACRO_EXPANSION",
        None,
        None,
        RegionCoverage::Unsupported,
        span,
    );
}

fn observe_signature(signature: &syn::Signature, facts: &mut Vec<SourceProfileFact>) {
    if signature.asyncness.is_some() {
        push_fact(
            facts,
            "ASYNC_FUNCTION",
            Some(signature.ident.to_string()),
            None,
            RegionCoverage::Observed,
            signature.span(),
        );
    }
    let output = signature.output.to_token_stream().to_string();
    if output.contains("Result") || output.trim() == "-> !" {
        push_fact(
            facts,
            "FAILURE_BEARING_SURFACE",
            Some(signature.ident.to_string()),
            None,
            RegionCoverage::Observed,
            signature.output.span(),
        );
    }
}

fn regions_for_fact(path: &str, fact: &SourceProfileFact) -> Vec<SourceObservation> {
    let regions: &[SemanticRegion] = match fact.kind.as_str() {
        "USE_DECLARATION" | "EXTERN_CRATE" => &[SemanticRegion::Dependencies],
        "CONSTANT_DECLARATION" | "STATIC_DECLARATION" => &[
            SemanticRegion::Declarations,
            SemanticRegion::State,
            SemanticRegion::Initialization,
        ],
        "INHERENT_IMPL"
        | "TRAIT_IMPL"
        | "METHOD_IMPLEMENTATION"
        | "FUNCTION_IMPLEMENTATION"
        | "TEST_FUNCTION"
        | "ASYNC_FUNCTION"
        | "MACRO_INVOCATION" => &[SemanticRegion::Implementation],
        "FAILURE_BEARING_SURFACE" => &[SemanticRegion::FailureSemantics],
        "PUBLIC_SURFACE" => &[SemanticRegion::PublicInterface],
        "DOC_ATTRIBUTE" => &[SemanticRegion::DocumentationIntent],
        _ => &[SemanticRegion::Declarations],
    };
    let mut observations = regions
        .iter()
        .map(|region| {
            SourceObservation::new(
                path,
                *region,
                fact.coverage,
                ADAPTER,
                fact.source_reference.clone(),
                fact.start_line,
            )
        })
        .collect::<Vec<_>>();
    if fact
        .visibility
        .as_deref()
        .is_some_and(|value| value != "PRIVATE")
    {
        observations.push(SourceObservation::new(
            path,
            SemanticRegion::PublicInterface,
            RegionCoverage::Observed,
            ADAPTER,
            fact.source_reference.clone(),
            fact.start_line,
        ));
    }
    observations
}

fn push_named(
    facts: &mut Vec<SourceProfileFact>,
    kind: &str,
    name: &syn::Ident,
    item_visibility: &Visibility,
    span: proc_macro2::Span,
) {
    push_fact(
        facts,
        kind,
        Some(name.to_string()),
        Some(visibility(item_visibility)),
        RegionCoverage::Observed,
        span,
    );
}

fn push_attribute(facts: &mut Vec<SourceProfileFact>, attribute: &Attribute, kind: &str) {
    let name = attribute
        .path()
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::");
    push_fact(
        facts,
        if attribute.path().is_ident("doc") {
            "DOC_ATTRIBUTE"
        } else {
            kind
        },
        Some(name),
        None,
        RegionCoverage::Observed,
        attribute.span(),
    );
}

fn push_fact(
    facts: &mut Vec<SourceProfileFact>,
    kind: &str,
    name: Option<String>,
    visibility: Option<String>,
    coverage: RegionCoverage,
    span: proc_macro2::Span,
) {
    let line = u32::try_from(span.start().line).ok();
    let reference = format!(
        "rust:{}:{}:{}",
        kind,
        name.as_deref().unwrap_or("_"),
        visibility.as_deref().unwrap_or("NOT_APPLICABLE")
    );
    facts.push(SourceProfileFact::new(
        RUST_SOURCE_PROFILE_ID,
        kind,
        name,
        visibility,
        coverage,
        reference,
        line,
    ));
}

fn visibility(value: &Visibility) -> String {
    match value {
        Visibility::Public(_) => "PUB".into(),
        Visibility::Inherited => "PRIVATE".into(),
        Visibility::Restricted(restricted) => {
            let path = restricted
                .path
                .to_token_stream()
                .to_string()
                .replace(' ', "");
            if path == "crate" {
                "PUB_CRATE".into()
            } else if path == "super" {
                "PUB_SUPER".into()
            } else if path == "self" {
                "PUB_SELF".into()
            } else {
                format!("PUB_IN:{path}")
            }
        }
    }
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(value) => &value.attrs,
        Item::Enum(value) => &value.attrs,
        Item::ExternCrate(value) => &value.attrs,
        Item::Fn(value) => &value.attrs,
        Item::ForeignMod(value) => &value.attrs,
        Item::Impl(value) => &value.attrs,
        Item::Macro(value) => &value.attrs,
        Item::Mod(value) => &value.attrs,
        Item::Static(value) => &value.attrs,
        Item::Struct(value) => &value.attrs,
        Item::Trait(value) => &value.attrs,
        Item::TraitAlias(value) => &value.attrs,
        Item::Type(value) => &value.attrs,
        Item::Union(value) => &value.attrs,
        Item::Use(value) => &value.attrs,
        _ => &[],
    }
}
