//! Snapshot-bound Rust translation into language-neutral PSM facts.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use proc_macro2::Span;
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Block, Expr, FnArg, GenericArgument, GenericParam, ImplItem, Item, Pat,
    PathArguments, ReturnType, Signature, TraitItem, Type, UseTree, Visibility,
};

use crate::implementation_observation::SourceOwnership;

use super::{
    CallResolutionReason, CallResolutionState, CallSiteEvidence, ExecutableSymbol,
    ExecutableSymbolKind, ImplResolutionState, InterfaceType, MutationKind, NominalField,
    NominalType, NominalTypeKind, NominalVariant, PlaceResolutionState, ProgramBody, ProgramCall,
    ProgramExpression, ProgramImpl, ProgramImplKind, ProgramMatchArm, ProgramMutation,
    ProgramPackage, ProgramParameter, ProgramPattern, ProgramPlace, ProgramProvenance,
    ProgramReceiver, ProgramSemanticError, ProgramSemanticInput, ProgramSourceInput,
    ProgramSourceLocation, ProgramStatement, ProgramTarget, ProgramType, RUST_PROGRAM_ANALYZER_ID,
    ResolutionAuthority, RustProgramFacts, SemanticType, StateRead, SymbolBodyState,
    SymbolClassification, SymbolQualifiers, SymbolVisibility, TransferResolutionState,
    TransformationKind, TypeResolution, TypeTransformation, ValueEndpoint, ValueTransfer,
    ValueTransferKind, canonical_fact_id,
};

#[derive(Deserialize)]
struct CargoDocument {
    package: Option<CargoPackageDocument>,
    lib: Option<CargoTargetDocument>,
    #[serde(default)]
    bin: Vec<CargoTargetDocument>,
    #[serde(default)]
    test: Vec<CargoTargetDocument>,
    #[serde(default)]
    dependencies: BTreeMap<String, CargoDependencyDocument>,
    #[serde(rename = "dev-dependencies", default)]
    dev_dependencies: BTreeMap<String, CargoDependencyDocument>,
    #[serde(rename = "build-dependencies", default)]
    build_dependencies: BTreeMap<String, CargoDependencyDocument>,
}

#[derive(Deserialize)]
struct CargoPackageDocument {
    name: String,
}

#[derive(Default, Deserialize)]
struct CargoTargetDocument {
    name: Option<String>,
    path: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum CargoDependencyDocument {
    Version(String),
    Detailed(CargoDependencyDetail),
}

#[derive(Clone, Default, Deserialize)]
struct CargoDependencyDetail {
    path: Option<String>,
    package: Option<String>,
}

#[derive(Clone)]
struct CargoPackage {
    name: String,
    manifest_path: String,
    lib_name: String,
    lib_root: Option<String>,
    targets: Vec<CargoTarget>,
    dependencies: BTreeMap<String, DependencyResolution>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CargoTarget {
    crate_name: String,
    root: String,
    kind: String,
}

#[derive(Clone)]
enum DependencyResolution {
    WorkspacePackage(String),
    External(String),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SourceContext {
    package_name: String,
    package_manifest: String,
    target_root: String,
    crate_name: String,
    namespace: Vec<String>,
}

#[derive(Clone)]
struct BodyFact {
    symbol: String,
    source_path: String,
    context: SourceContext,
    owner_type: Option<String>,
    aliases: BTreeMap<String, Vec<String>>,
    parameter_types: BTreeMap<String, InterfaceType>,
    return_type: InterfaceType,
    block: Block,
}

#[derive(Serialize)]
struct SymbolIdentity<'a> {
    language: &'static str,
    package: &'a str,
    crate_name: &'a str,
    namespace: &'a [String],
    owner_type: &'a Option<String>,
    owner_trait: &'a Option<String>,
    name: String,
    signature: String,
}

#[derive(Serialize)]
struct TransformationIdentity<'a> {
    symbol: &'a str,
    kind: TransformationKind,
    provenance: &'a ProgramProvenance,
}

struct FunctionInterface {
    parameters: Vec<ProgramParameter>,
    parameter_types: BTreeMap<String, InterfaceType>,
    return_type: InterfaceType,
    receiver: Option<ProgramReceiver>,
    generic_parameters: Vec<String>,
    lifetimes: Vec<String>,
}

#[derive(Default)]
struct TypeRegistry {
    types: BTreeMap<String, (SemanticType, BTreeSet<String>)>,
}

impl TypeRegistry {
    fn register(&mut self, syntax: &Type, generics: &BTreeSet<String>) -> InterfaceType {
        let spelling = syntax.to_token_stream().to_string();
        let semantic = normalize_type(syntax, generics);
        self.register_semantic(semantic, spelling)
    }

    fn register_with_aliases(
        &mut self,
        syntax: &Type,
        generics: &BTreeSet<String>,
        aliases: &BTreeMap<String, Vec<String>>,
    ) -> InterfaceType {
        let spelling = syntax.to_token_stream().to_string();
        let semantic = resolve_semantic_aliases(normalize_type(syntax, generics), aliases);
        self.register_semantic(semantic, spelling)
    }

    fn register_semantic(
        &mut self,
        semantic: SemanticType,
        spelling: impl Into<String>,
    ) -> InterfaceType {
        let spelling = spelling.into();
        let id = canonical_fact_id("type", &semantic);
        let resolution = if matches!(semantic, SemanticType::Unknown { .. }) {
            TypeResolution::Unsupported
        } else {
            TypeResolution::DeclaredExact
        };
        self.types
            .entry(id.clone())
            .or_insert_with(|| (semantic, BTreeSet::new()))
            .1
            .insert(spelling.clone());
        InterfaceType::new(id, spelling, resolution)
    }

    fn finish(self) -> Vec<ProgramType> {
        self.types
            .into_iter()
            .map(|(id, (semantic, spellings))| {
                ProgramType::new(id, semantic, spellings.into_iter().collect())
            })
            .collect()
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn analyze(
    input: &ProgramSemanticInput,
) -> Result<RustProgramFacts, ProgramSemanticError> {
    let files = verified_files(input)?;
    let source_inputs = semantic_source_inputs(&files);
    let source_identity = semantic_source_identity(&source_inputs);
    let mut packages = parse_packages(&files)?;
    resolve_dependencies(&mut packages);
    let source_owners = source_owners(input.observation().ownerships());
    let source_contexts = build_source_contexts(&packages, &files)?;
    let package_by_manifest: BTreeMap<&str, &CargoPackage> = packages
        .iter()
        .map(|package| (package.manifest_path.as_str(), package))
        .collect();
    let mut registry = TypeRegistry::default();
    let mut symbols = Vec::new();
    let mut nominal_types = Vec::new();
    let mut impls = Vec::new();
    let mut bodies = Vec::new();
    let mut parameter_transfers = Vec::new();
    let mut reexports = BTreeMap::new();
    for (path, contexts) in &source_contexts {
        let source = rust_source(path, files[path])?;
        let syntax = parse_rust(path, source)?;
        let owner = source_owners
            .get(path)
            .ok_or_else(|| ProgramSemanticError::MissingSourceOwner(path.clone()))?;
        for context in contexts {
            let package = package_by_manifest[context.package_manifest.as_str()];
            let classification = if input.testing_modules().contains(owner) {
                SymbolClassification::Testing
            } else {
                SymbolClassification::Production
            };
            let mut collection = SymbolCollection {
                package,
                context,
                owner,
                classification,
                source_path: path,
                registry: &mut registry,
                symbols: &mut symbols,
                nominal_types: &mut nominal_types,
                impls: &mut impls,
                bodies: &mut bodies,
                transfers: &mut parameter_transfers,
                reexports: &mut reexports,
            };
            collection.collect_items(&syntax.items, &context.namespace, &BTreeMap::new());
        }
    }
    canonicalize_declarations(&mut symbols, &mut nominal_types, &mut impls);
    resolve_impl_states(&mut impls, &nominal_types, &registry);
    bodies.sort_by(|left, right| left.symbol.cmp(&right.symbol));
    bodies.dedup_by(|left, right| left.symbol == right.symbol);
    let lookup = SymbolLookup::new(
        &symbols,
        &nominal_types,
        &packages,
        &source_owners,
        reexports,
    );
    let mut raw_calls = Vec::new();
    let mut value_transfers = parameter_transfers;
    let mut transformations = Vec::new();
    let mut state_reads = Vec::new();
    let mut mutations = Vec::new();
    let mut program_bodies = Vec::new();
    for body in &bodies {
        program_bodies.push(lower_program_body(body));
        BodyAnalyzer::new(
            body,
            &lookup,
            &mut registry,
            &mut raw_calls,
            &mut value_transfers,
            &mut transformations,
            &mut state_reads,
            &mut mutations,
        )
        .analyze();
    }
    let calls = resolve_calls(raw_calls, &lookup, &mut value_transfers, &mut registry);
    value_transfers.sort();
    value_transfers.dedup();
    transformations.sort();
    transformations.dedup();
    state_reads.sort();
    state_reads.dedup();
    mutations.sort();
    mutations.dedup();
    Ok(RustProgramFacts {
        source_identity,
        source_inputs,
        source_files: source_contexts.len(),
        packages: package_facts(&packages),
        nominal_types,
        impls,
        symbols,
        types: registry.finish(),
        calls,
        bodies: program_bodies,
        value_transfers,
        transformations,
        state_reads,
        mutations,
        fixed_point_iterations: 1,
    })
}

fn canonicalize_declarations(
    symbols: &mut Vec<ExecutableSymbol>,
    nominal_types: &mut Vec<NominalType>,
    impls: &mut Vec<ProgramImpl>,
) {
    symbols.sort();
    symbols.dedup();
    nominal_types.sort();
    nominal_types.dedup();
    impls.sort();
    impls.dedup();
}

fn lower_program_body(body: &BodyFact) -> ProgramBody {
    ProgramBody {
        symbol: body.symbol.clone(),
        statements: lower_block(body, &body.block),
        provenance: provenance(
            &body.source_path,
            body.block.span(),
            Some(body.symbol.clone()),
        ),
    }
}

fn resolve_impl_states(
    impls: &mut [ProgramImpl],
    nominal_types: &[NominalType],
    registry: &TypeRegistry,
) {
    let local = nominal_types
        .iter()
        .map(|nominal| {
            (
                nominal.package.as_str(),
                simple_type_name(&nominal.qualified_name),
            )
        })
        .collect::<BTreeSet<_>>();
    for implementation in impls {
        let self_semantic = registry
            .types
            .get(&implementation.self_type.type_id)
            .map(|value| &value.0);
        let self_local = self_semantic
            .and_then(semantic_type_name)
            .is_some_and(|name| {
                local.contains(&(implementation.package.as_str(), simple_type_name(&name)))
            });
        let trait_local = implementation.trait_type.as_ref().is_none_or(|interface| {
            registry
                .types
                .get(&interface.type_id)
                .map(|value| &value.0)
                .and_then(semantic_type_name)
                .is_some_and(|name| {
                    local.contains(&(implementation.package.as_str(), simple_type_name(&name)))
                })
        });
        implementation.resolution = if self_semantic
            .is_some_and(|semantic| matches!(semantic, SemanticType::Unknown { .. }))
        {
            ImplResolutionState::Unresolved
        } else if self_local && trait_local {
            ImplResolutionState::ResolvedLocal
        } else {
            ImplResolutionState::ExternalOrGeneric
        };
    }
}

fn lower_block(body: &BodyFact, block: &Block) -> Vec<ProgramStatement> {
    block
        .stmts
        .iter()
        .enumerate()
        .flat_map(|(index, statement)| {
            let is_tail = index + 1 == block.stmts.len();
            lower_statement(body, statement, is_tail)
        })
        .collect()
}

fn lower_statement(body: &BodyFact, statement: &syn::Stmt, is_tail: bool) -> Vec<ProgramStatement> {
    match statement {
        syn::Stmt::Local(local) => vec![ProgramStatement::Let {
            pattern: lower_pattern(&local.pat),
            value: local
                .init
                .as_ref()
                .map(|initializer| lower_expression(&initializer.expr)),
            provenance: body_provenance(body, local.span()),
        }],
        syn::Stmt::Item(_) => Vec::new(),
        syn::Stmt::Macro(statement) => vec![ProgramStatement::Expression {
            value: lower_macro(&statement.mac.path.to_token_stream().to_string()),
            provenance: body_provenance(body, statement.span()),
        }],
        syn::Stmt::Expr(expression, semi) => {
            if is_tail
                && semi.is_none()
                && !matches!(expression, Expr::If(_) | Expr::Match(_) | Expr::Return(_))
            {
                return vec![ProgramStatement::Return {
                    value: Some(lower_expression(expression)),
                    provenance: body_provenance(body, expression.span()),
                }];
            }
            lower_expression_statement(body, expression)
        }
    }
}

fn lower_expression_statement(body: &BodyFact, expression: &Expr) -> Vec<ProgramStatement> {
    match expression {
        Expr::Assign(value) => vec![ProgramStatement::Assign {
            target: value.left.to_token_stream().to_string(),
            value: lower_expression(&value.right),
            provenance: body_provenance(body, value.span()),
        }],
        Expr::Return(value) => vec![ProgramStatement::Return {
            value: value.expr.as_deref().map(lower_expression),
            provenance: body_provenance(body, value.span()),
        }],
        Expr::If(value) => {
            let else_branch = value.else_branch.as_ref().map_or_else(
                Vec::new,
                |(_, expression)| match expression.as_ref() {
                    Expr::Block(block) => lower_block(body, &block.block),
                    nested => lower_expression_statement(body, nested),
                },
            );
            vec![ProgramStatement::If {
                condition: lower_expression(&value.cond),
                then_branch: lower_block(body, &value.then_branch),
                else_branch,
                provenance: body_provenance(body, value.span()),
            }]
        }
        Expr::Match(value) => vec![ProgramStatement::Match {
            value: lower_expression(&value.expr),
            arms: value
                .arms
                .iter()
                .map(|arm| ProgramMatchArm {
                    pattern: lower_pattern(&arm.pat),
                    guard: arm.guard.as_ref().map(|(_, guard)| lower_expression(guard)),
                    body: match arm.body.as_ref() {
                        Expr::Block(block) => lower_block(body, &block.block),
                        Expr::Return(value) => vec![ProgramStatement::Return {
                            value: value.expr.as_deref().map(lower_expression),
                            provenance: body_provenance(body, value.span()),
                        }],
                        expression => vec![ProgramStatement::Return {
                            value: Some(lower_expression(expression)),
                            provenance: body_provenance(body, expression.span()),
                        }],
                    },
                    provenance: body_provenance(body, arm.span()),
                })
                .collect(),
            provenance: body_provenance(body, value.span()),
        }],
        Expr::While(value) => {
            let Expr::Let(predicate) = value.cond.as_ref() else {
                return vec![ProgramStatement::Expression {
                    value: ProgramExpression::Unsupported {
                        rust_spelling: expression.to_token_stream().to_string(),
                    },
                    provenance: body_provenance(body, expression.span()),
                }];
            };
            vec![ProgramStatement::WhileLet {
                pattern: lower_pattern(&predicate.pat),
                value: lower_expression(&predicate.expr),
                body: lower_block(body, &value.body),
                provenance: body_provenance(body, value.span()),
            }]
        }
        _ => vec![ProgramStatement::Expression {
            value: lower_expression(expression),
            provenance: body_provenance(body, expression.span()),
        }],
    }
}

fn lower_expression(expression: &Expr) -> ProgramExpression {
    match expression {
        Expr::Paren(value) => lower_expression(&value.expr),
        Expr::Group(value) => lower_expression(&value.expr),
        Expr::Path(value) => {
            let name = value.path.to_token_stream().to_string();
            if value.path.segments.len() == 1
                && value
                    .path
                    .segments
                    .first()
                    .is_some_and(|segment| starts_lowercase(&segment.ident.to_string()))
            {
                ProgramExpression::Binding { name }
            } else {
                ProgramExpression::Variant { name }
            }
        }
        Expr::Lit(value) => match &value.lit {
            syn::Lit::Bool(value) => ProgramExpression::Boolean { value: value.value },
            syn::Lit::Int(value) => ProgramExpression::Integer {
                value: value.to_token_stream().to_string(),
            },
            _ => ProgramExpression::Unsupported {
                rust_spelling: expression.to_token_stream().to_string(),
            },
        },
        Expr::Tuple(value) if value.elems.is_empty() => ProgramExpression::Unit,
        Expr::Tuple(value) => ProgramExpression::Tuple {
            elements: value.elems.iter().map(lower_expression).collect(),
        },
        Expr::Field(value) => ProgramExpression::Field {
            base: Box::new(lower_expression(&value.base)),
            field: value.member.to_token_stream().to_string(),
        },
        Expr::Call(value) => {
            let reference = value.func.to_token_stream().to_string();
            let arguments = value.args.iter().map(lower_expression).collect();
            if matches!(reference.rsplit("::").next(), Some("Some" | "Ok" | "Err")) {
                ProgramExpression::Construction {
                    constructor: reference,
                    arguments,
                }
            } else {
                ProgramExpression::Call {
                    reference,
                    arguments,
                }
            }
        }
        Expr::Let(value) => ProgramExpression::PatternTest {
            pattern: lower_pattern(&value.pat),
            value: Box::new(lower_expression(&value.expr)),
        },
        Expr::MethodCall(value) => ProgramExpression::MethodCall {
            receiver: Box::new(lower_expression(&value.receiver)),
            method: value.method.to_string(),
            arguments: value.args.iter().map(lower_expression).collect(),
        },
        Expr::Binary(value) => ProgramExpression::Binary {
            operator: value.op.to_token_stream().to_string(),
            left: Box::new(lower_expression(&value.left)),
            right: Box::new(lower_expression(&value.right)),
        },
        Expr::Unary(value) => ProgramExpression::Unary {
            operator: value.op.to_token_stream().to_string(),
            value: Box::new(lower_expression(&value.expr)),
        },
        Expr::Try(value) => ProgramExpression::Try {
            value: Box::new(lower_expression(&value.expr)),
        },
        Expr::Reference(value) => ProgramExpression::Reference {
            mutable: value.mutability.is_some(),
            value: Box::new(lower_expression(&value.expr)),
        },
        Expr::Macro(value) => lower_macro(&value.mac.path.to_token_stream().to_string()),
        Expr::Block(value) => value
            .block
            .stmts
            .last()
            .and_then(|statement| match statement {
                syn::Stmt::Expr(value, _) => Some(lower_expression(value)),
                _ => None,
            })
            .unwrap_or(ProgramExpression::Unit),
        _ => ProgramExpression::Unsupported {
            rust_spelling: expression.to_token_stream().to_string(),
        },
    }
}

fn lower_pattern(pattern: &Pat) -> ProgramPattern {
    match pattern {
        Pat::Wild(_) => ProgramPattern::Wildcard,
        Pat::Ident(value) => ProgramPattern::Binding {
            name: value.ident.to_string(),
        },
        Pat::Path(value) => ProgramPattern::Variant {
            name: value.path.to_token_stream().to_string(),
            fields: Vec::new(),
        },
        Pat::Tuple(value) => ProgramPattern::Tuple {
            elements: value.elems.iter().map(lower_pattern).collect(),
        },
        Pat::TupleStruct(value) => ProgramPattern::Variant {
            name: value.path.to_token_stream().to_string(),
            fields: value.elems.iter().map(lower_pattern).collect(),
        },
        Pat::Struct(value) => ProgramPattern::Variant {
            name: value.path.to_token_stream().to_string(),
            fields: value
                .fields
                .iter()
                .map(|field| lower_pattern(&field.pat))
                .collect(),
        },
        Pat::Type(value) => lower_pattern(&value.pat),
        _ => ProgramPattern::Unsupported {
            rust_spelling: pattern.to_token_stream().to_string(),
        },
    }
}

fn lower_macro(path: &str) -> ProgramExpression {
    let operation = match path {
        "unreachable" => "unreachable",
        "panic" => "panic",
        _ => {
            return ProgramExpression::Unsupported {
                rust_spelling: format!("{path}!(...)"),
            };
        }
    };
    ProgramExpression::Exceptional {
        operation: operation.into(),
    }
}

fn body_provenance(body: &BodyFact, span: Span) -> ProgramProvenance {
    provenance(&body.source_path, span, Some(body.symbol.clone()))
}

fn starts_lowercase(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_lowercase() || character == '_')
}

fn verified_files(
    input: &ProgramSemanticInput,
) -> Result<BTreeMap<String, &[u8]>, ProgramSemanticError> {
    input
        .observation()
        .files()
        .iter()
        .map(|file| Ok((file.path().to_owned(), file.verified_bytes()?)))
        .collect()
}

fn is_rust_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
}

fn semantic_source_inputs(files: &BTreeMap<String, &[u8]>) -> Vec<ProgramSourceInput> {
    files
        .iter()
        .filter(|(path, _)| {
            is_rust_path(path)
                || path.ends_with("Cargo.toml")
                || path.as_str() == "contract.json"
                || path.ends_with("/contract.json")
        })
        .map(|(path, bytes)| ProgramSourceInput {
            path: path.clone(),
            sha256: format!("sha256:{:x}", Sha256::digest(bytes)),
        })
        .collect()
}

fn semantic_source_identity(inputs: &[ProgramSourceInput]) -> String {
    #[derive(Serialize)]
    struct Identity<'a> {
        analyzer: &'static str,
        version: &'static str,
        inputs: &'a [ProgramSourceInput],
    }
    let bytes = serde_json::to_vec(&Identity {
        analyzer: RUST_PROGRAM_ANALYZER_ID,
        version: super::RUST_PROGRAM_ANALYZER_VERSION,
        inputs,
    })
    .expect("PSM source identity is serializable");
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn rust_source<'a>(path: &str, bytes: &'a [u8]) -> Result<&'a str, ProgramSemanticError> {
    std::str::from_utf8(bytes).map_err(|_| ProgramSemanticError::NonUtf8Rust(path.into()))
}

fn parse_rust(path: &str, source: &str) -> Result<syn::File, ProgramSemanticError> {
    syn::parse_file(source).map_err(|source| ProgramSemanticError::InvalidRustSource {
        path: path.into(),
        source,
    })
}

fn parse_packages(
    files: &BTreeMap<String, &[u8]>,
) -> Result<Vec<CargoPackage>, ProgramSemanticError> {
    let mut packages = Vec::new();
    for (path, bytes) in files
        .iter()
        .filter(|(path, _)| path.ends_with("Cargo.toml"))
    {
        let source = std::str::from_utf8(bytes)
            .map_err(|_| ProgramSemanticError::NonUtf8Rust(path.clone()))?;
        let mut document: CargoDocument = toml::from_str(source).map_err(|source| {
            ProgramSemanticError::InvalidCargoManifest {
                path: path.clone(),
                source,
            }
        })?;
        let Some(package) = document.package.take() else {
            continue;
        };
        packages.push(package_from_document(path, package, document, files));
    }
    packages.sort_by(|left, right| left.manifest_path.cmp(&right.manifest_path));
    Ok(packages)
}

fn package_from_document(
    manifest_path: &str,
    package: CargoPackageDocument,
    document: CargoDocument,
    files: &BTreeMap<String, &[u8]>,
) -> CargoPackage {
    let manifest_dir = parent_path(manifest_path);
    let lib_name = document
        .lib
        .as_ref()
        .and_then(|target| target.name.clone())
        .unwrap_or_else(|| rust_crate_name(&package.name));
    let lib_root = document.lib.as_ref().map_or_else(
        || {
            let default = join_path(&manifest_dir, "src/lib.rs");
            files.contains_key(&default).then_some(default)
        },
        |target| {
            Some(resolve_cargo_target_path(
                &manifest_dir,
                target.path.as_deref().unwrap_or("src/lib.rs"),
                files,
            ))
        },
    );
    let mut targets = Vec::new();
    if let Some(root) = &lib_root {
        targets.push(CargoTarget {
            crate_name: lib_name.clone(),
            root: root.clone(),
            kind: "library".into(),
        });
    }
    targets.extend(document.bin.iter().filter_map(|target| {
        target.path.as_ref().map(|path| CargoTarget {
            crate_name: rust_crate_name(target.name.as_deref().unwrap_or(&package.name)),
            root: resolve_cargo_target_path(&manifest_dir, path, files),
            kind: "binary".into(),
        })
    }));
    targets.extend(document.test.iter().filter_map(|target| {
        target.path.as_ref().map(|path| CargoTarget {
            crate_name: rust_crate_name(target.name.as_deref().unwrap_or("test")),
            root: resolve_cargo_target_path(&manifest_dir, path, files),
            kind: "test".into(),
        })
    }));
    let default_main = join_path(&manifest_dir, "src/main.rs");
    if document.bin.is_empty() && files.contains_key(&default_main) {
        targets.push(CargoTarget {
            crate_name: rust_crate_name(&package.name),
            root: default_main,
            kind: "binary".into(),
        });
    }
    targets.sort();
    targets.dedup();
    let mut dependency_documents = document.dependencies;
    dependency_documents.extend(document.dev_dependencies);
    dependency_documents.extend(document.build_dependencies);
    let dependencies = dependency_documents
        .into_iter()
        .map(|(alias, dependency)| {
            let rust_alias = rust_crate_name(&alias);
            let resolution = match dependency {
                CargoDependencyDocument::Version(version) => {
                    let _ = version;
                    DependencyResolution::External(alias)
                }
                CargoDependencyDocument::Detailed(detail) => {
                    if let Some(path) = detail.path {
                        DependencyResolution::WorkspacePackage(join_path(
                            &manifest_dir,
                            &format!("{path}/Cargo.toml"),
                        ))
                    } else {
                        DependencyResolution::External(detail.package.unwrap_or(alias))
                    }
                }
            };
            (rust_alias, resolution)
        })
        .collect();
    CargoPackage {
        name: package.name,
        manifest_path: manifest_path.into(),
        lib_name,
        lib_root,
        targets,
        dependencies,
    }
}

fn resolve_cargo_target_path(
    manifest_dir: &str,
    declared_path: &str,
    files: &BTreeMap<String, &[u8]>,
) -> String {
    let direct = join_path(manifest_dir, declared_path);
    [
        direct.clone(),
        format!("{direct}.rs"),
        format!("{direct}/mod.rs"),
    ]
    .into_iter()
    .find_map(|candidate| resolve_observed_path(&candidate, files))
    .unwrap_or(direct)
}

fn resolve_dependencies(packages: &mut [CargoPackage]) {
    let known: BTreeMap<String, String> = packages
        .iter()
        .map(|package| (package.manifest_path.clone(), package.name.clone()))
        .collect();
    for package in packages {
        for resolution in package.dependencies.values_mut() {
            if let DependencyResolution::WorkspacePackage(manifest) = resolution {
                if let Some(name) = known.get(manifest) {
                    *resolution = DependencyResolution::WorkspacePackage(name.clone());
                } else {
                    *resolution = DependencyResolution::External(manifest.clone());
                }
            }
        }
    }
}

fn package_facts(packages: &[CargoPackage]) -> Vec<ProgramPackage> {
    packages
        .iter()
        .map(|package| {
            let targets = package
                .targets
                .iter()
                .map(|target| {
                    ProgramTarget::new(
                        target.crate_name.clone(),
                        target.kind.clone(),
                        target.root.clone(),
                    )
                })
                .collect();
            let mut workspace = Vec::new();
            let mut external = Vec::new();
            for dependency in package.dependencies.values() {
                match dependency {
                    DependencyResolution::WorkspacePackage(name) => workspace.push(name.clone()),
                    DependencyResolution::External(name) => external.push(name.clone()),
                }
            }
            ProgramPackage::new(
                package.name.clone(),
                package.manifest_path.clone(),
                targets,
                workspace,
                external,
            )
        })
        .collect()
}

fn source_owners(ownerships: &[SourceOwnership]) -> BTreeMap<String, String> {
    ownerships
        .iter()
        .map(|ownership| {
            (
                ownership.source_path().to_owned(),
                ownership.owner().to_owned(),
            )
        })
        .collect()
}

fn build_source_contexts(
    packages: &[CargoPackage],
    files: &BTreeMap<String, &[u8]>,
) -> Result<BTreeMap<String, Vec<SourceContext>>, ProgramSemanticError> {
    let mut contexts = BTreeMap::<String, Vec<SourceContext>>::new();
    for package in packages {
        for target in &package.targets {
            if !files.contains_key(&target.root) {
                return Err(ProgramSemanticError::MissingTargetSource(
                    target.root.clone(),
                ));
            }
            discover_module_tree(&target.root, &[], files, &mut contexts, package, target)?;
        }
    }
    for values in contexts.values_mut() {
        values.sort();
        values.dedup();
    }
    Ok(contexts)
}

fn discover_module_tree(
    path: &str,
    namespace: &[String],
    files: &BTreeMap<String, &[u8]>,
    contexts: &mut BTreeMap<String, Vec<SourceContext>>,
    package: &CargoPackage,
    target: &CargoTarget,
) -> Result<(), ProgramSemanticError> {
    contexts
        .entry(path.into())
        .or_default()
        .push(SourceContext {
            package_name: package.name.clone(),
            package_manifest: package.manifest_path.clone(),
            target_root: target.root.clone(),
            crate_name: target.crate_name.clone(),
            namespace: namespace.to_vec(),
        });
    let syntax = parse_rust(path, rust_source(path, files[path])?)?;
    let mut queue = VecDeque::new();
    collect_modules(
        &syntax.items,
        path,
        path == target.root,
        namespace,
        &mut queue,
    );
    while let Some(module) = queue.pop_front() {
        match module {
            DiscoveredModule::Inline { namespace, items } => {
                collect_modules(&items, path, path == target.root, &namespace, &mut queue);
            }
            DiscoveredModule::External {
                namespace,
                declared_path,
            } => {
                let target_path = resolve_module_file(path, &declared_path, files)
                    .ok_or(ProgramSemanticError::MissingTargetSource(declared_path))?;
                discover_module_tree(&target_path, &namespace, files, contexts, package, target)?;
            }
        }
    }
    Ok(())
}

enum DiscoveredModule {
    Inline {
        namespace: Vec<String>,
        items: Vec<Item>,
    },
    External {
        namespace: Vec<String>,
        declared_path: String,
    },
}

fn collect_modules(
    items: &[Item],
    source_path: &str,
    crate_root: bool,
    namespace: &[String],
    queue: &mut VecDeque<DiscoveredModule>,
) {
    for item in items {
        let Item::Mod(module) = item else {
            continue;
        };
        let mut child = namespace.to_vec();
        child.push(module.ident.to_string());
        if let Some((_, items)) = &module.content {
            queue.push_back(DiscoveredModule::Inline {
                namespace: child,
                items: items.clone(),
            });
        } else {
            queue.push_back(DiscoveredModule::External {
                namespace: child,
                declared_path: module_path_attribute(&module.attrs).unwrap_or_else(|| {
                    default_module_path(source_path, &module.ident.to_string(), crate_root)
                }),
            });
        }
    }
}

fn module_path_attribute(attributes: &[Attribute]) -> Option<String> {
    attributes.iter().find_map(|attribute| {
        if attribute.path().is_ident("cfg_attr") {
            let mut configured_path = None;
            let parsed = attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("path") {
                    configured_path = Some(meta.value()?.parse::<syn::LitStr>()?.value());
                }
                Ok(())
            });
            if parsed.is_ok() && configured_path.is_some() {
                return configured_path;
            }
        } else if !attribute.path().is_ident("path") {
            return None;
        }
        let syn::Meta::NameValue(value) = &attribute.meta else {
            return None;
        };
        let Expr::Lit(literal) = &value.value else {
            return None;
        };
        let syn::Lit::Str(path) = &literal.lit else {
            return None;
        };
        Some(path.value())
    })
}

fn default_module_path(source_path: &str, module: &str, crate_root: bool) -> String {
    let filename = source_path.rsplit('/').next().unwrap_or(source_path);
    if crate_root || matches!(filename, "lib.rs" | "main.rs" | "mod.rs") {
        module.into()
    } else {
        let stem = filename.strip_suffix(".rs").unwrap_or(filename);
        format!("{stem}/{module}")
    }
}

fn resolve_module_file(
    source_path: &str,
    declared_path: &str,
    files: &BTreeMap<String, &[u8]>,
) -> Option<String> {
    if files.contains_key(declared_path) {
        return Some(declared_path.into());
    }
    let direct = join_path(&parent_path(source_path), declared_path);
    [
        direct.clone(),
        format!("{direct}.rs"),
        format!("{direct}/mod.rs"),
    ]
    .into_iter()
    .find_map(|candidate| resolve_observed_path(&candidate, files))
}

fn resolve_observed_path(candidate: &str, files: &BTreeMap<String, &[u8]>) -> Option<String> {
    if files.contains_key(candidate) {
        return Some(candidate.into());
    }
    let segments = candidate.split('/').collect::<Vec<_>>();
    for boundary in (1..segments.len()).rev() {
        let prefix = segments[..boundary].join("/");
        let Some(bytes) = files.get(&prefix) else {
            continue;
        };
        let Ok(target) = std::str::from_utf8(bytes) else {
            continue;
        };
        let target = target.trim();
        let drive_path = target.as_bytes().get(1) == Some(&b':');
        if target.is_empty()
            || target.contains(char::is_whitespace)
            || target.starts_with('/')
            || target.contains('\\')
            || drive_path
        {
            continue;
        }
        let alias_root = join_path(&parent_path(&prefix), target);
        let resolved = join_path(&alias_root, &segments[boundary..].join("/"));
        if files.contains_key(&resolved) {
            return Some(resolved);
        }
    }
    None
}

struct SymbolCollection<'a> {
    package: &'a CargoPackage,
    context: &'a SourceContext,
    owner: &'a str,
    classification: SymbolClassification,
    source_path: &'a str,
    registry: &'a mut TypeRegistry,
    symbols: &'a mut Vec<ExecutableSymbol>,
    nominal_types: &'a mut Vec<NominalType>,
    impls: &'a mut Vec<ProgramImpl>,
    bodies: &'a mut Vec<BodyFact>,
    transfers: &'a mut Vec<ValueTransfer>,
    reexports: &'a mut BTreeMap<ReexportKey, Vec<String>>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReexportKey {
    package: String,
    crate_name: String,
    namespace: Vec<String>,
    alias: String,
}

impl SymbolCollection<'_> {
    fn collect_items(
        &mut self,
        items: &[Item],
        namespace: &[String],
        inherited_aliases: &BTreeMap<String, Vec<String>>,
    ) {
        let aliases = self.collect_aliases(items, namespace, inherited_aliases);
        for item in items {
            self.collect_item(item, namespace, &aliases);
        }
    }

    fn collect_aliases(
        &mut self,
        items: &[Item],
        namespace: &[String],
        inherited: &BTreeMap<String, Vec<String>>,
    ) -> BTreeMap<String, Vec<String>> {
        let mut aliases = inherited.clone();
        for item_use in items.iter().filter_map(|item| match item {
            Item::Use(value) => Some(value),
            _ => None,
        }) {
            let mut expanded = Vec::new();
            expand_use_tree(Vec::new(), &item_use.tree, &mut expanded);
            for (path, alias) in expanded {
                aliases.insert(alias.clone(), path.clone());
                if matches!(item_use.vis, Visibility::Public(_)) {
                    self.reexports.insert(
                        ReexportKey {
                            package: self.package.name.clone(),
                            crate_name: self.context.crate_name.clone(),
                            namespace: namespace.to_vec(),
                            alias,
                        },
                        path,
                    );
                }
            }
        }
        aliases
    }

    fn collect_item(
        &mut self,
        item: &Item,
        namespace: &[String],
        aliases: &BTreeMap<String, Vec<String>>,
    ) {
        match item {
            Item::Fn(function) => {
                self.add_function(
                    namespace,
                    &function.sig,
                    &function.vis,
                    ExecutableSymbolKind::FreeFunction,
                    None,
                    None,
                    Some(function.block.as_ref().clone()),
                    aliases,
                    &BTreeSet::new(),
                );
            }
            Item::Struct(value) => self.collect_struct(value, namespace, aliases),
            Item::Enum(value) => self.collect_enum(value, namespace, aliases),
            Item::Type(value) => self.collect_type_alias(value, namespace, aliases),
            Item::Impl(value) => self.collect_impl(value, namespace, aliases),
            Item::Trait(value) => self.collect_trait(value, namespace, aliases),
            Item::Mod(module) => {
                if let Some((_, child_items)) = &module.content {
                    let mut child_namespace = namespace.to_vec();
                    child_namespace.push(module.ident.to_string());
                    self.collect_items(child_items, &child_namespace, &BTreeMap::new());
                }
            }
            _ => {}
        }
    }

    fn collect_struct(
        &mut self,
        value: &syn::ItemStruct,
        namespace: &[String],
        aliases: &BTreeMap<String, Vec<String>>,
    ) {
        let generics = generic_names(&value.generics.params);
        let fields = self.nominal_fields(&value.fields, &generics, aliases);
        self.add_nominal(
            namespace,
            &value.ident.to_string(),
            NominalTypeKind::Struct,
            generics,
            fields,
            Vec::new(),
            Vec::new(),
            None,
            value.ident.span(),
        );
    }

    fn collect_enum(
        &mut self,
        value: &syn::ItemEnum,
        namespace: &[String],
        aliases: &BTreeMap<String, Vec<String>>,
    ) {
        let generics = generic_names(&value.generics.params);
        let variants = value
            .variants
            .iter()
            .map(|variant| NominalVariant {
                name: variant.ident.to_string(),
                fields: self.nominal_fields(&variant.fields, &generics, aliases),
                provenance: provenance(
                    self.source_path,
                    variant.ident.span(),
                    Some(variant.ident.to_string()),
                ),
            })
            .collect();
        self.add_nominal(
            namespace,
            &value.ident.to_string(),
            NominalTypeKind::Enum,
            generics,
            Vec::new(),
            variants,
            Vec::new(),
            None,
            value.ident.span(),
        );
    }

    fn collect_type_alias(
        &mut self,
        value: &syn::ItemType,
        namespace: &[String],
        aliases: &BTreeMap<String, Vec<String>>,
    ) {
        let generics = generic_names(&value.generics.params);
        let target = self
            .registry
            .register_with_aliases(&value.ty, &generics, aliases);
        self.add_nominal(
            namespace,
            &value.ident.to_string(),
            NominalTypeKind::TypeAlias,
            generics,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(target),
            value.ident.span(),
        );
    }

    fn collect_impl(
        &mut self,
        value: &syn::ItemImpl,
        namespace: &[String],
        aliases: &BTreeMap<String, Vec<String>>,
    ) {
        let owner_type = value.self_ty.to_token_stream().to_string();
        let owner_trait = value
            .trait_
            .as_ref()
            .map(|(_, path, _)| path.to_token_stream().to_string());
        let impl_generics = generic_names(&value.generics.params);
        let mut method_ids = value
            .items
            .iter()
            .filter_map(|item| match item {
                ImplItem::Fn(function) => Some(self.add_impl_method(
                    function,
                    namespace,
                    aliases,
                    &impl_generics,
                    &owner_type,
                    owner_trait.as_deref(),
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        method_ids.sort();
        let self_type =
            self.registry
                .register_with_aliases(&value.self_ty, &impl_generics, aliases);
        let trait_type = value.trait_.as_ref().map(|(_, path, _)| {
            self.registry.register_with_aliases(
                &Type::Path(syn::TypePath {
                    qself: None,
                    path: path.clone(),
                }),
                &impl_generics,
                aliases,
            )
        });
        let kind = if trait_type.is_some() {
            ProgramImplKind::Trait
        } else {
            ProgramImplKind::Inherent
        };
        self.impls.push(ProgramImpl {
            id: canonical_fact_id(
                "rust_impl",
                &(
                    &self.package.name,
                    &self.context.crate_name,
                    namespace,
                    &owner_type,
                    &owner_trait,
                    &method_ids,
                ),
            ),
            package: self.package.name.clone(),
            crate_name: self.context.crate_name.clone(),
            rust_module: namespace.join("::"),
            fortress_module: self.owner.into(),
            kind,
            self_type,
            trait_type,
            generic_parameters: impl_generics.into_iter().collect(),
            methods: method_ids,
            resolution: ImplResolutionState::Unresolved,
            provenance: provenance(self.source_path, value.impl_token.span(), Some(owner_type)),
        });
    }

    fn add_impl_method(
        &mut self,
        function: &syn::ImplItemFn,
        namespace: &[String],
        aliases: &BTreeMap<String, Vec<String>>,
        impl_generics: &BTreeSet<String>,
        owner_type: &str,
        owner_trait: Option<&str>,
    ) -> String {
        let kind = if owner_trait.is_some() {
            ExecutableSymbolKind::TraitMethodImplementation
        } else if function.sig.receiver().is_some() {
            ExecutableSymbolKind::InherentMethod
        } else {
            ExecutableSymbolKind::AssociatedFunction
        };
        self.add_function(
            namespace,
            &function.sig,
            &function.vis,
            kind,
            Some(owner_type.into()),
            owner_trait.map(str::to_owned),
            Some(function.block.clone()),
            aliases,
            impl_generics,
        )
    }

    fn collect_trait(
        &mut self,
        value: &syn::ItemTrait,
        namespace: &[String],
        aliases: &BTreeMap<String, Vec<String>>,
    ) {
        let owner_trait = value.ident.to_string();
        let trait_generics = generic_names(&value.generics.params);
        let mut method_ids = value
            .items
            .iter()
            .filter_map(|item| match item {
                TraitItem::Fn(function) => Some(self.add_function(
                    namespace,
                    &function.sig,
                    &Visibility::Public(syn::token::Pub::default()),
                    ExecutableSymbolKind::TraitMethodDeclaration,
                    None,
                    Some(owner_trait.clone()),
                    function.default.clone(),
                    aliases,
                    &trait_generics,
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        method_ids.sort();
        self.add_nominal(
            namespace,
            &owner_trait,
            NominalTypeKind::Trait,
            trait_generics,
            Vec::new(),
            Vec::new(),
            method_ids,
            None,
            value.ident.span(),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn add_function(
        &mut self,
        namespace: &[String],
        signature: &Signature,
        visibility: &Visibility,
        kind: ExecutableSymbolKind,
        owner_type: Option<String>,
        owner_trait: Option<String>,
        block: Option<Block>,
        aliases: &BTreeMap<String, Vec<String>>,
        surrounding_generics: &BTreeSet<String>,
    ) -> String {
        let FunctionInterface {
            parameters,
            parameter_types,
            return_type,
            receiver,
            generic_parameters,
            lifetimes,
        } = self.function_interface(signature, surrounding_generics, aliases);
        let qualified_name = qualified_name(
            &self.context.crate_name,
            namespace,
            owner_type.as_deref().or(owner_trait.as_deref()),
            &signature.ident.to_string(),
        );
        let id = canonical_fact_id(
            "rust_symbol",
            &SymbolIdentity {
                language: "rust",
                package: &self.package.name,
                crate_name: &self.context.crate_name,
                namespace,
                owner_type: &owner_type,
                owner_trait: &owner_trait,
                name: signature.ident.to_string(),
                signature: signature.to_token_stream().to_string(),
            },
        );
        let symbol_provenance = provenance(
            self.source_path,
            signature.ident.span(),
            Some(qualified_name.clone()),
        );
        self.transfers.extend(parameter_transfers(&id, &parameters));
        let symbol = ExecutableSymbol {
            id: id.clone(),
            qualified_name,
            language: "rust".into(),
            package: self.package.name.clone(),
            crate_name: self.context.crate_name.clone(),
            rust_module: namespace.join("::"),
            fortress_module: self.owner.into(),
            classification: self.classification,
            source_path: self.source_path.into(),
            kind,
            owner_type: owner_type.clone(),
            owner_trait,
            parameters,
            return_type: return_type.clone(),
            receiver,
            generic_parameters,
            lifetimes,
            qualifiers: SymbolQualifiers::new(
                signature.asyncness.is_some(),
                signature.unsafety.is_some(),
                signature.constness.is_some(),
            ),
            visibility: normalize_visibility(visibility),
            body_state: if block.is_some() {
                SymbolBodyState::Definition
            } else {
                SymbolBodyState::Declaration
            },
            provenance: symbol_provenance,
        };
        if let Some(block) = block {
            self.bodies.push(BodyFact {
                symbol: id.clone(),
                source_path: self.source_path.into(),
                context: SourceContext {
                    namespace: namespace.to_vec(),
                    ..self.context.clone()
                },
                owner_type,
                aliases: aliases.clone(),
                parameter_types,
                return_type,
                block,
            });
        }
        self.symbols.push(symbol);
        id
    }

    fn nominal_fields(
        &mut self,
        fields: &syn::Fields,
        generics: &BTreeSet<String>,
        aliases: &BTreeMap<String, Vec<String>>,
    ) -> Vec<NominalField> {
        fields
            .iter()
            .enumerate()
            .map(|(position, field)| NominalField {
                name: field
                    .ident
                    .as_ref()
                    .map_or_else(|| position.to_string(), ToString::to_string),
                position,
                field_type: self
                    .registry
                    .register_with_aliases(&field.ty, generics, aliases),
                provenance: provenance(
                    self.source_path,
                    field.span(),
                    field.ident.as_ref().map(ToString::to_string),
                ),
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn add_nominal(
        &mut self,
        namespace: &[String],
        name: &str,
        kind: NominalTypeKind,
        generic_parameters: BTreeSet<String>,
        fields: Vec<NominalField>,
        variants: Vec<NominalVariant>,
        trait_methods: Vec<String>,
        alias_target: Option<InterfaceType>,
        span: Span,
    ) {
        let qualified_name = qualified_name(&self.context.crate_name, namespace, None, name);
        self.nominal_types.push(NominalType {
            id: canonical_fact_id(
                "rust_nominal",
                &(
                    &self.package.name,
                    &self.context.crate_name,
                    namespace,
                    name,
                    kind,
                ),
            ),
            qualified_name: qualified_name.clone(),
            language: "rust".into(),
            package: self.package.name.clone(),
            crate_name: self.context.crate_name.clone(),
            rust_module: namespace.join("::"),
            fortress_module: self.owner.into(),
            kind,
            generic_parameters: generic_parameters.into_iter().collect(),
            fields,
            variants,
            trait_methods,
            alias_transparent: alias_target.is_some(),
            alias_target,
            provenance: provenance(self.source_path, span, Some(qualified_name)),
        });
    }

    fn function_interface(
        &mut self,
        signature: &Signature,
        surrounding_generics: &BTreeSet<String>,
        aliases: &BTreeMap<String, Vec<String>>,
    ) -> FunctionInterface {
        let mut generics = surrounding_generics.clone();
        generics.extend(generic_names(&signature.generics.params));
        let generic_parameters = generics.iter().cloned().collect::<Vec<_>>();
        let lifetimes = signature
            .generics
            .params
            .iter()
            .filter_map(|parameter| match parameter {
                GenericParam::Lifetime(lifetime) => Some(lifetime.lifetime.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut parameters = Vec::new();
        let mut parameter_types = BTreeMap::new();
        let mut receiver = None;
        for input in &signature.inputs {
            match input {
                FnArg::Receiver(value) => {
                    let explicit_type = value.colon_token.is_some().then(|| {
                        self.registry
                            .register_with_aliases(&value.ty, &generics, aliases)
                    });
                    receiver = Some(ProgramReceiver::new(
                        value.mutability.is_some(),
                        value.reference.is_some(),
                        explicit_type,
                    ));
                }
                FnArg::Typed(value) => {
                    let position = parameters.len();
                    let name = pattern_name(&value.pat);
                    let parameter_type = self
                        .registry
                        .register_with_aliases(&value.ty, &generics, aliases);
                    let source = provenance(
                        self.source_path,
                        value.pat.span(),
                        Some(signature.ident.to_string()),
                    );
                    if let Some(binding) = simple_pattern_name(&value.pat) {
                        parameter_types.insert(binding, parameter_type.clone());
                    }
                    parameters.push(ProgramParameter::new(
                        position,
                        name,
                        parameter_type,
                        source,
                    ));
                }
            }
        }
        let return_type = match &signature.output {
            ReturnType::Default => self.registry.register_semantic(SemanticType::Unit, "()"),
            ReturnType::Type(_, output) => self
                .registry
                .register_with_aliases(output, &generics, aliases),
        };
        FunctionInterface {
            parameters,
            parameter_types,
            return_type,
            receiver,
            generic_parameters,
            lifetimes,
        }
    }
}

fn parameter_transfers(symbol: &str, parameters: &[ProgramParameter]) -> Vec<ValueTransfer> {
    parameters
        .iter()
        .map(|parameter| {
            make_transfer(
                ValueTransferKind::ParameterToBinding,
                ValueEndpoint::new(
                    symbol.into(),
                    "parameter",
                    format!("parameter:{}", parameter.position),
                    Some(parameter.parameter_type.type_id.clone()),
                ),
                ValueEndpoint::new(
                    symbol.into(),
                    "binding",
                    parameter.name.clone(),
                    Some(parameter.parameter_type.type_id.clone()),
                ),
                TransferResolutionState::SyntaxExact,
                parameter.provenance.clone(),
            )
        })
        .collect()
}

fn generic_names(
    parameters: &syn::punctuated::Punctuated<GenericParam, syn::token::Comma>,
) -> BTreeSet<String> {
    parameters
        .iter()
        .map(|parameter| match parameter {
            GenericParam::Type(value) => value.ident.to_string(),
            GenericParam::Const(value) => value.ident.to_string(),
            GenericParam::Lifetime(value) => value.lifetime.to_string(),
        })
        .collect()
}

fn pattern_name(pattern: &Pat) -> String {
    simple_pattern_name(pattern).unwrap_or_else(|| pattern.to_token_stream().to_string())
}

fn simple_pattern_name(pattern: &Pat) -> Option<String> {
    match pattern {
        Pat::Ident(value) => Some(value.ident.to_string()),
        Pat::Type(value) => simple_pattern_name(&value.pat),
        _ => None,
    }
}

fn qualified_name(
    crate_name: &str,
    namespace: &[String],
    owner: Option<&str>,
    name: &str,
) -> String {
    std::iter::once(crate_name)
        .chain(namespace.iter().map(String::as_str))
        .chain(owner)
        .chain(std::iter::once(name))
        .collect::<Vec<_>>()
        .join("::")
}

fn normalize_visibility(visibility: &Visibility) -> SymbolVisibility {
    match visibility {
        Visibility::Public(_) => SymbolVisibility::Public,
        Visibility::Inherited => SymbolVisibility::Private,
        Visibility::Restricted(restricted) if restricted.path.is_ident("crate") => {
            SymbolVisibility::Crate
        }
        Visibility::Restricted(restricted) => {
            SymbolVisibility::Restricted(restricted.to_token_stream().to_string())
        }
    }
}

fn provenance(path: &str, span: Span, symbol_context: Option<String>) -> ProgramProvenance {
    let start = span.start();
    ProgramProvenance::rust(
        path,
        ProgramSourceLocation::new(
            u32::try_from(start.line).unwrap_or(u32::MAX),
            u32::try_from(start.column.saturating_add(1)).unwrap_or(u32::MAX),
        ),
        symbol_context,
    )
}

fn make_transfer(
    kind: ValueTransferKind,
    producer: ValueEndpoint,
    consumer: ValueEndpoint,
    resolution: TransferResolutionState,
    provenance: ProgramProvenance,
) -> ValueTransfer {
    #[derive(Serialize)]
    struct Identity<'a> {
        kind: ValueTransferKind,
        producer: &'a ValueEndpoint,
        consumer: &'a ValueEndpoint,
        provenance: &'a ProgramProvenance,
    }
    let id = canonical_fact_id(
        "value_transfer",
        &Identity {
            kind,
            producer: &producer,
            consumer: &consumer,
            provenance: &provenance,
        },
    );
    ValueTransfer {
        id,
        kind,
        producer,
        consumer,
        resolution,
        provenance,
    }
}

fn normalize_type(syntax: &Type, generics: &BTreeSet<String>) -> SemanticType {
    match syntax {
        Type::Tuple(tuple) if tuple.elems.is_empty() => SemanticType::Unit,
        Type::Tuple(tuple) => SemanticType::Tuple {
            elements: tuple
                .elems
                .iter()
                .map(|element| normalize_type(element, generics))
                .collect(),
        },
        Type::Never(_) => SemanticType::Never,
        Type::Reference(reference) => SemanticType::Reference {
            mutable: reference.mutability.is_some(),
            lifetime: reference.lifetime.as_ref().map(ToString::to_string),
            target: Box::new(normalize_type(&reference.elem, generics)),
        },
        Type::Ptr(pointer) => SemanticType::Pointer {
            mutable: pointer.mutability.is_some(),
            target: Box::new(normalize_type(&pointer.elem, generics)),
        },
        Type::Slice(slice) => SemanticType::Slice {
            element: Box::new(normalize_type(&slice.elem, generics)),
        },
        Type::Array(array) => SemanticType::Array {
            element: Box::new(normalize_type(&array.elem, generics)),
            length: array.len.to_token_stream().to_string(),
        },
        Type::BareFn(function) => SemanticType::Function {
            parameters: function
                .inputs
                .iter()
                .map(|input| normalize_type(&input.ty, generics))
                .collect(),
            result: Box::new(match &function.output {
                ReturnType::Default => SemanticType::Unit,
                ReturnType::Type(_, output) => normalize_type(output, generics),
            }),
        },
        Type::Path(path) if path.qself.is_none() => normalize_path_type(&path.path, generics),
        Type::Paren(paren) => normalize_type(&paren.elem, generics),
        Type::Group(group) => normalize_type(&group.elem, generics),
        _ => SemanticType::Unknown {
            rust_spelling: syntax.to_token_stream().to_string(),
        },
    }
}

fn resolve_semantic_aliases(
    semantic: SemanticType,
    aliases: &BTreeMap<String, Vec<String>>,
) -> SemanticType {
    match semantic {
        SemanticType::Named { name, arguments } => {
            let mut segments = name.split("::").map(str::to_owned).collect::<Vec<_>>();
            if let Some(prefix) = segments.first().and_then(|first| aliases.get(first)) {
                segments = prefix
                    .iter()
                    .cloned()
                    .chain(segments.into_iter().skip(1))
                    .collect();
            }
            SemanticType::Named {
                name: segments.join("::"),
                arguments: arguments
                    .into_iter()
                    .map(|value| resolve_semantic_aliases(value, aliases))
                    .collect(),
            }
        }
        SemanticType::Tuple { elements } => SemanticType::Tuple {
            elements: elements
                .into_iter()
                .map(|value| resolve_semantic_aliases(value, aliases))
                .collect(),
        },
        SemanticType::Array { element, length } => SemanticType::Array {
            element: Box::new(resolve_semantic_aliases(*element, aliases)),
            length,
        },
        SemanticType::Slice { element } => SemanticType::Slice {
            element: Box::new(resolve_semantic_aliases(*element, aliases)),
        },
        SemanticType::Reference {
            mutable,
            lifetime,
            target,
        } => SemanticType::Reference {
            mutable,
            lifetime,
            target: Box::new(resolve_semantic_aliases(*target, aliases)),
        },
        SemanticType::Pointer { mutable, target } => SemanticType::Pointer {
            mutable,
            target: Box::new(resolve_semantic_aliases(*target, aliases)),
        },
        SemanticType::Option { value } => SemanticType::Option {
            value: Box::new(resolve_semantic_aliases(*value, aliases)),
        },
        SemanticType::Result { success, error } => SemanticType::Result {
            success: Box::new(resolve_semantic_aliases(*success, aliases)),
            error: Box::new(resolve_semantic_aliases(*error, aliases)),
        },
        SemanticType::Function { parameters, result } => SemanticType::Function {
            parameters: parameters
                .into_iter()
                .map(|value| resolve_semantic_aliases(value, aliases))
                .collect(),
            result: Box::new(resolve_semantic_aliases(*result, aliases)),
        },
        value => value,
    }
}

fn normalize_path_type(path: &syn::Path, generics: &BTreeSet<String>) -> SemanticType {
    let spelling = path.to_token_stream().to_string();
    let Some(last) = path.segments.last() else {
        return SemanticType::Unknown {
            rust_spelling: spelling,
        };
    };
    let name = last.ident.to_string();
    if generics.contains(&name) {
        return SemanticType::GenericParameter { name };
    }
    let arguments = type_arguments(&last.arguments, generics);
    match name.as_str() {
        "bool" => SemanticType::Bool,
        "char" => SemanticType::Char,
        "str" => SemanticType::String {
            representation: "str".into(),
        },
        "String" => SemanticType::String {
            representation: "owned".into(),
        },
        "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "u8" | "u16" | "u32" | "u64" | "u128"
        | "usize" => SemanticType::Integer { family: name },
        "f32" | "f64" => SemanticType::Float { family: name },
        "Option" if arguments.len() == 1 => SemanticType::Option {
            value: Box::new(arguments[0].clone()),
        },
        "Result" if arguments.len() == 2 => SemanticType::Result {
            success: Box::new(arguments[0].clone()),
            error: Box::new(arguments[1].clone()),
        },
        _ => SemanticType::Named {
            name: spelling_without_arguments(path),
            arguments,
        },
    }
}

fn type_arguments(arguments: &PathArguments, generics: &BTreeSet<String>) -> Vec<SemanticType> {
    let PathArguments::AngleBracketed(arguments) = arguments else {
        return Vec::new();
    };
    arguments
        .args
        .iter()
        .filter_map(|argument| match argument {
            GenericArgument::Type(value) => Some(normalize_type(value, generics)),
            _ => None,
        })
        .collect()
}

fn spelling_without_arguments(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn expand_use_tree(prefix: Vec<String>, tree: &UseTree, output: &mut Vec<(Vec<String>, String)>) {
    match tree {
        UseTree::Path(path) => {
            let mut next = prefix;
            next.push(path.ident.to_string());
            expand_use_tree(next, &path.tree, output);
        }
        UseTree::Name(name) => {
            let mut path = prefix;
            let alias = name.ident.to_string();
            path.push(alias.clone());
            output.push((path, alias));
        }
        UseTree::Rename(rename) => {
            let mut path = prefix;
            path.push(rename.ident.to_string());
            output.push((path, rename.rename.to_string()));
        }
        UseTree::Group(group) => {
            for item in &group.items {
                expand_use_tree(prefix.clone(), item, output);
            }
        }
        UseTree::Glob(_) => {}
    }
}

fn rust_crate_name(value: &str) -> String {
    value.replace('-', "_")
}

fn parent_path(path: &str) -> String {
    path.rsplit_once('/')
        .map_or_else(String::new, |(parent, _)| parent.into())
}

fn join_path(base: &str, value: &str) -> String {
    let mut segments = base
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for segment in value.replace('\\', "/").split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(segment.into()),
        }
    }
    segments.join("/")
}

#[derive(Clone)]
struct PackageLookup {
    lib_name: String,
    facade_owner: Option<String>,
    dependencies: BTreeMap<String, DependencyResolution>,
}

struct SymbolLookup {
    path_to_symbols: BTreeMap<(String, String, Vec<String>), Vec<String>>,
    methods: BTreeMap<(String, String, String), Vec<String>>,
    symbols: BTreeMap<String, ExecutableSymbol>,
    packages: BTreeMap<String, PackageLookup>,
    reexports: BTreeMap<ReexportKey, Vec<String>>,
    nominal_fields: BTreeMap<(String, String, String), InterfaceType>,
    local_nominals: BTreeSet<(String, String)>,
    nominal_ids: BTreeMap<(String, String), String>,
    nominal_aliases: BTreeMap<(String, String), InterfaceType>,
}

impl SymbolLookup {
    fn new(
        symbols: &[ExecutableSymbol],
        nominal_types: &[NominalType],
        packages: &[CargoPackage],
        source_owners: &BTreeMap<String, String>,
        reexports: BTreeMap<ReexportKey, Vec<String>>,
    ) -> Self {
        let mut path_to_symbols = BTreeMap::<_, Vec<String>>::new();
        let mut methods = BTreeMap::<_, Vec<String>>::new();
        for symbol in symbols.iter().filter(|symbol| symbol.has_body()) {
            let mut path = split_namespace(&symbol.rust_module);
            if let Some(owner) = symbol
                .owner_type
                .as_deref()
                .or(symbol.owner_trait.as_deref())
            {
                path.push(simple_type_name(owner));
            }
            let name = symbol
                .qualified_name
                .rsplit("::")
                .next()
                .unwrap_or(&symbol.qualified_name)
                .to_owned();
            path.push(name.clone());
            path_to_symbols
                .entry((symbol.package.clone(), symbol.crate_name.clone(), path))
                .or_default()
                .push(symbol.id.clone());
            if let Some(owner) = &symbol.owner_type {
                methods
                    .entry((symbol.package.clone(), simple_type_name(owner), name))
                    .or_default()
                    .push(symbol.id.clone());
            }
        }
        for values in path_to_symbols.values_mut() {
            values.sort();
            values.dedup();
        }
        for values in methods.values_mut() {
            values.sort();
            values.dedup();
        }
        let package_lookup = packages
            .iter()
            .map(|package| {
                let facade_owner = package
                    .lib_root
                    .as_ref()
                    .and_then(|path| source_owners.get(path))
                    .cloned();
                (
                    package.name.clone(),
                    PackageLookup {
                        lib_name: package.lib_name.clone(),
                        facade_owner,
                        dependencies: package.dependencies.clone(),
                    },
                )
            })
            .collect();
        let mut nominal_fields = BTreeMap::new();
        let mut local_nominals = BTreeSet::new();
        let mut nominal_ids = BTreeMap::new();
        let mut nominal_aliases = BTreeMap::new();
        for nominal in nominal_types {
            let simple = simple_type_name(&nominal.qualified_name);
            local_nominals.insert((nominal.package.clone(), simple.clone()));
            nominal_ids.insert(
                (nominal.package.clone(), simple.clone()),
                nominal.id.clone(),
            );
            for field in &nominal.fields {
                nominal_fields.insert(
                    (nominal.package.clone(), simple.clone(), field.name.clone()),
                    field.field_type.clone(),
                );
            }
            if nominal.kind == NominalTypeKind::TypeAlias
                && let Some(target) = &nominal.alias_target
            {
                nominal_aliases.insert((nominal.package.clone(), simple.clone()), target.clone());
            }
        }
        Self {
            path_to_symbols,
            methods,
            symbols: symbols
                .iter()
                .map(|symbol| (symbol.id.clone(), symbol.clone()))
                .collect(),
            packages: package_lookup,
            reexports,
            nominal_fields,
            local_nominals,
            nominal_ids,
            nominal_aliases,
        }
    }

    fn symbol(&self, id: &str) -> Option<&ExecutableSymbol> {
        self.symbols.get(id)
    }

    fn field_type(&self, package: &str, owner: &str, field: &str) -> Option<InterfaceType> {
        self.nominal_fields
            .get(&(package.into(), simple_type_name(owner), field.into()))
            .cloned()
    }

    fn is_local_nominal(&self, package: &str, owner: &str) -> bool {
        self.local_nominals
            .contains(&(package.into(), simple_type_name(owner)))
    }

    fn nominal_id(&self, package: &str, owner: &str) -> Option<&str> {
        self.nominal_ids
            .get(&(package.into(), simple_type_name(owner)))
            .map(String::as_str)
    }

    fn alias_target(&self, package: &str, owner: &str) -> Option<InterfaceType> {
        self.nominal_aliases
            .get(&(package.into(), simple_type_name(owner)))
            .cloned()
    }

    fn resolve_path(
        &self,
        package: &str,
        crate_name: &str,
        namespace: &[String],
        owner_type: Option<&str>,
        segments: &[String],
        qualified_self: bool,
    ) -> CallOutcome {
        if qualified_self {
            return CallOutcome::unsupported();
        }
        let Some(first) = segments.first() else {
            return CallOutcome::unresolved();
        };
        if first == "Self" {
            return owner_type.map_or_else(CallOutcome::unresolved, |owner| {
                self.resolve_method(package, owner, segments.last().map_or("", String::as_str))
            });
        }
        let current = &self.packages[package];
        if let Some(dependency) = current.dependencies.get(first) {
            return match dependency {
                DependencyResolution::WorkspacePackage(target_package) => {
                    let target = &self.packages[target_package];
                    self.resolve_in_scope(
                        target_package,
                        &target.lib_name,
                        &[],
                        &segments[1..],
                        target.facade_owner.clone(),
                    )
                }
                DependencyResolution::External(target) => CallOutcome::external(target.clone()),
            };
        }
        if first == &current.lib_name && crate_name != current.lib_name {
            return self.resolve_in_scope(
                package,
                &current.lib_name,
                &[],
                &segments[1..],
                current.facade_owner.clone(),
            );
        }
        if matches!(first.as_str(), "std" | "core" | "alloc") {
            return CallOutcome::external(first.clone());
        }
        let normalized = normalize_relative_path(namespace, segments);
        let outcome = self.resolve_in_scope(package, crate_name, namespace, &normalized, None);
        if outcome.state == CallResolutionState::ResolvedStatic {
            return outcome;
        }
        if segments.len() >= 2 && starts_type_name(first) {
            let method = segments.last().map_or("", String::as_str);
            let owner = segments[..segments.len() - 1].join("::");
            let outcome = self.resolve_method(package, &owner, method);
            if outcome.state == CallResolutionState::ResolvedStatic {
                return outcome;
            }
            if is_standard_type(&owner) {
                return CallOutcome::external(owner);
            }
        }
        if matches!(first.as_str(), "Some" | "Ok" | "Err" | "Box") {
            return CallOutcome::external(format!("rust_prelude::{first}"));
        }
        outcome
    }

    fn resolve_in_scope(
        &self,
        package: &str,
        crate_name: &str,
        namespace: &[String],
        path: &[String],
        boundary_target_module: Option<String>,
    ) -> CallOutcome {
        let mut candidates = Vec::new();
        let mut attempted = Vec::new();
        if path.first().is_some_and(|value| value == "crate") {
            attempted.push(path[1..].to_vec());
        } else if path.first().is_some_and(|value| value == "self") {
            attempted.push(
                namespace
                    .iter()
                    .cloned()
                    .chain(path.iter().skip(1).cloned())
                    .collect(),
            );
        } else if path.first().is_some_and(|value| value == "super") {
            attempted.push(normalize_relative_path(namespace, path));
        } else {
            attempted.push(path.to_vec());
            attempted.push(
                namespace
                    .iter()
                    .cloned()
                    .chain(path.iter().cloned())
                    .collect(),
            );
        }
        attempted.sort();
        attempted.dedup();
        for candidate in attempted {
            candidates.extend(self.resolve_reexport(package, crate_name, &candidate, 0));
        }
        candidates.sort();
        candidates.dedup();
        match candidates.len().cmp(&1) {
            Ordering::Equal => CallOutcome::resolved(candidates.remove(0), boundary_target_module),
            Ordering::Greater => CallOutcome::ambiguous(candidates),
            Ordering::Less => CallOutcome::unresolved(),
        }
    }

    fn resolve_reexport(
        &self,
        package: &str,
        crate_name: &str,
        path: &[String],
        depth: usize,
    ) -> Vec<String> {
        if depth > 8 {
            return Vec::new();
        }
        if let Some(symbols) =
            self.path_to_symbols
                .get(&(package.into(), crate_name.into(), path.to_vec()))
        {
            return symbols.clone();
        }
        for split in (0..path.len()).rev() {
            let namespace = path[..split].to_vec();
            let alias = &path[split];
            let key = ReexportKey {
                package: package.into(),
                crate_name: crate_name.into(),
                namespace: namespace.clone(),
                alias: alias.clone(),
            };
            if let Some(target) = self.reexports.get(&key) {
                let mut expanded = normalize_relative_path(&namespace, target);
                expanded.extend_from_slice(&path[split + 1..]);
                return self.resolve_reexport(package, crate_name, &expanded, depth + 1);
            }
        }
        Vec::new()
    }

    fn resolve_method(&self, package: &str, owner: &str, method: &str) -> CallOutcome {
        let simple_owner = simple_type_name(owner);
        let key = (package.into(), simple_owner.clone(), method.into());
        let mut candidates = self.methods.get(&key).cloned().unwrap_or_default();
        let mut boundary_target_module = None;
        if candidates.is_empty()
            && let Some(crate_name) = owner.split("::").next()
            && let Some(DependencyResolution::WorkspacePackage(target_package)) = self
                .packages
                .get(package)
                .and_then(|current| current.dependencies.get(crate_name))
            && let Some(target) = self.packages.get(target_package)
        {
            candidates = self
                .methods
                .get(&(target_package.clone(), simple_owner, method.into()))
                .cloned()
                .unwrap_or_default();
            boundary_target_module.clone_from(&target.facade_owner);
        }
        match candidates.as_slice() {
            [callee] => CallOutcome::resolved(callee.clone(), boundary_target_module),
            [] => CallOutcome::unresolved(),
            _ => CallOutcome::ambiguous(candidates),
        }
    }
}

#[derive(Clone)]
struct RawArgument {
    label: String,
    type_id: Option<String>,
    provenance: ProgramProvenance,
}

#[derive(Clone)]
enum RawCallTarget {
    Path {
        segments: Vec<String>,
        qualified_self: bool,
    },
    Method {
        method: String,
        receiver_type: Option<String>,
        receiver_display: String,
        receiver_reason: Option<CallResolutionReason>,
    },
    Dynamic,
    Macro,
}

#[derive(Clone)]
struct RawCall {
    caller: String,
    package: String,
    crate_name: String,
    namespace: Vec<String>,
    owner_type: Option<String>,
    target: RawCallTarget,
    reference: String,
    arguments: Vec<RawArgument>,
    consumer: Option<ValueEndpoint>,
    evidence: CallSiteEvidence,
}

#[derive(Clone)]
struct CallOutcome {
    state: CallResolutionState,
    authority: ResolutionAuthority,
    reason: Option<CallResolutionReason>,
    callee: Option<String>,
    boundary_target_module: Option<String>,
    external_target: Option<String>,
    candidates: Vec<String>,
}

impl CallOutcome {
    fn resolved(callee: String, boundary_target_module: Option<String>) -> Self {
        Self {
            state: CallResolutionState::ResolvedStatic,
            authority: ResolutionAuthority::StructuralExact,
            reason: None,
            callee: Some(callee),
            boundary_target_module,
            external_target: None,
            candidates: Vec::new(),
        }
    }

    fn external(target: String) -> Self {
        Self {
            state: CallResolutionState::External,
            authority: ResolutionAuthority::ExactExternalOwner,
            reason: Some(CallResolutionReason::ExternalReceiver),
            callee: None,
            boundary_target_module: None,
            external_target: Some(target),
            candidates: Vec::new(),
        }
    }

    fn dynamic(candidates: Vec<String>) -> Self {
        Self {
            state: CallResolutionState::DynamicDispatch,
            authority: ResolutionAuthority::ConservativeCandidateSet,
            reason: Some(CallResolutionReason::UnresolvedTraitSelection),
            callee: None,
            boundary_target_module: None,
            external_target: None,
            candidates,
        }
    }

    fn unresolved() -> Self {
        Self {
            state: CallResolutionState::Unresolved,
            authority: ResolutionAuthority::InsufficientTypeInformation,
            reason: Some(CallResolutionReason::UnknownPath),
            callee: None,
            boundary_target_module: None,
            external_target: None,
            candidates: Vec::new(),
        }
    }

    fn unsupported() -> Self {
        Self {
            state: CallResolutionState::Unsupported,
            authority: ResolutionAuthority::Unsupported,
            reason: Some(CallResolutionReason::UnsupportedSyntax),
            callee: None,
            boundary_target_module: None,
            external_target: None,
            candidates: Vec::new(),
        }
    }

    fn ambiguous(candidates: Vec<String>) -> Self {
        Self {
            state: CallResolutionState::Unresolved,
            authority: ResolutionAuthority::InsufficientTypeInformation,
            reason: Some(CallResolutionReason::AmbiguousLocalMethod),
            callee: None,
            boundary_target_module: None,
            external_target: None,
            candidates,
        }
    }

    fn with_reason(mut self, reason: CallResolutionReason) -> Self {
        self.reason = Some(reason);
        self
    }
}

fn split_namespace(value: &str) -> Vec<String> {
    value
        .split("::")
        .filter(|segment| !segment.is_empty())
        .map(str::to_owned)
        .collect()
}

fn simple_type_name(value: &str) -> String {
    let without_arguments = value.split('<').next().unwrap_or(value);
    without_arguments
        .rsplit("::")
        .next()
        .unwrap_or(without_arguments)
        .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .into()
}

fn semantic_type_name(value: &SemanticType) -> Option<String> {
    match value {
        SemanticType::Named { name, .. } | SemanticType::GenericParameter { name } => {
            Some(name.clone())
        }
        SemanticType::Option { .. } => Some("Option".into()),
        SemanticType::Result { .. } => Some("Result".into()),
        SemanticType::String { representation } if representation == "owned" => {
            Some("String".into())
        }
        SemanticType::String { representation } => Some(representation.clone()),
        _ => None,
    }
}

fn starts_type_name(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_uppercase())
}

fn is_standard_type(value: &str) -> bool {
    matches!(
        simple_type_name(value).as_str(),
        "String"
            | "Vec"
            | "Box"
            | "BTreeMap"
            | "BTreeSet"
            | "HashMap"
            | "HashSet"
            | "Option"
            | "Result"
            | "Path"
            | "PathBuf"
            | "str"
    )
}

fn normalize_relative_path(namespace: &[String], path: &[String]) -> Vec<String> {
    let mut result = namespace.to_vec();
    let mut index = 0;
    if path.first().is_some_and(|value| value == "crate") {
        result.clear();
        index = 1;
    } else if path.first().is_some_and(|value| value == "self") {
        index = 1;
    } else {
        while path.get(index).is_some_and(|value| value == "super") {
            result.pop();
            index += 1;
        }
    }
    result.extend(path[index..].iter().cloned());
    result
}

struct BodyAnalyzer<'a> {
    body: &'a BodyFact,
    lookup: &'a SymbolLookup,
    registry: &'a mut TypeRegistry,
    raw_calls: &'a mut Vec<RawCall>,
    transfers: &'a mut Vec<ValueTransfer>,
    transformations: &'a mut Vec<TypeTransformation>,
    state_reads: &'a mut Vec<StateRead>,
    mutations: &'a mut Vec<ProgramMutation>,
    local_types: BTreeMap<String, InterfaceType>,
    direct_consumer: Option<(SpanKey, ValueEndpoint)>,
    write_target: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SpanKey {
    line: usize,
    column: usize,
}

impl SpanKey {
    fn from_span(span: Span) -> Self {
        let start = span.start();
        Self {
            line: start.line,
            column: start.column,
        }
    }
}

impl<'a> BodyAnalyzer<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        body: &'a BodyFact,
        lookup: &'a SymbolLookup,
        registry: &'a mut TypeRegistry,
        raw_calls: &'a mut Vec<RawCall>,
        transfers: &'a mut Vec<ValueTransfer>,
        transformations: &'a mut Vec<TypeTransformation>,
        state_reads: &'a mut Vec<StateRead>,
        mutations: &'a mut Vec<ProgramMutation>,
    ) -> Self {
        let mut local_types = body.parameter_types.clone();
        if let Some(owner) = &body.owner_type {
            let interface = registry.register_semantic(
                SemanticType::Named {
                    name: owner.clone(),
                    arguments: Vec::new(),
                },
                owner.clone(),
            );
            local_types.insert("self".into(), interface);
        }
        Self {
            body,
            lookup,
            registry,
            raw_calls,
            transfers,
            transformations,
            state_reads,
            mutations,
            local_types,
            direct_consumer: None,
            write_target: false,
        }
    }

    fn analyze(mut self) {
        if let Some(syn::Stmt::Expr(expression, None)) = self.body.block.stmts.last() {
            self.transfer_to_return(expression, expression.span());
        }
        self.visit_block(&self.body.block);
    }

    fn expand_alias(&self, segments: &[String]) -> Vec<String> {
        let Some(first) = segments.first() else {
            return Vec::new();
        };
        self.body.aliases.get(first).map_or_else(
            || segments.to_vec(),
            |prefix| {
                prefix
                    .iter()
                    .cloned()
                    .chain(segments.iter().skip(1).cloned())
                    .collect()
            },
        )
    }

    fn expression_type(&mut self, expression: &Expr) -> Option<InterfaceType> {
        match expression {
            Expr::Paren(value) => self.expression_type(&value.expr),
            Expr::Group(value) => self.expression_type(&value.expr),
            Expr::Path(value) => self.path_expression_type(value),
            Expr::Lit(value) => self.literal_type(&value.lit),
            Expr::Reference(value) => self.reference_type(value),
            Expr::Unary(value) if matches!(value.op, syn::UnOp::Deref(_)) => {
                self.dereference_type(value)
            }
            Expr::Tuple(value) => self.tuple_expression_type(value),
            Expr::Struct(value) => Some(self.struct_expression_type(value)),
            Expr::Field(value) => self.field_expression_type(value),
            Expr::Call(call) => self.call_return_type(call),
            Expr::MethodCall(call) => self.method_return_type(call),
            Expr::Try(value) => self.try_expression_type(value),
            Expr::If(value) => self.if_expression_type(value),
            Expr::Match(value) => self.match_expression_type(value),
            _ => None,
        }
    }

    fn path_expression_type(&mut self, value: &syn::ExprPath) -> Option<InterfaceType> {
        if value.path.segments.len() == 1
            && let Some(local) = self
                .local_types
                .get(&value.path.segments[0].ident.to_string())
        {
            return Some(local.clone());
        }
        let segments = self.expand_alias(
            &value
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>(),
        );
        let spelling = segments.join("::");
        segments
            .last()
            .is_some_and(|segment| starts_type_name(segment))
            .then(|| {
                self.registry.register_semantic(
                    SemanticType::Named {
                        name: spelling.clone(),
                        arguments: Vec::new(),
                    },
                    spelling,
                )
            })
    }

    fn literal_type(&mut self, value: &syn::Lit) -> Option<InterfaceType> {
        let semantic = match value {
            syn::Lit::Bool(_) => SemanticType::Bool,
            syn::Lit::Char(_) => SemanticType::Char,
            syn::Lit::Str(_) => SemanticType::Reference {
                mutable: false,
                lifetime: Some("'static".into()),
                target: Box::new(SemanticType::String {
                    representation: "str".into(),
                }),
            },
            syn::Lit::Int(value) => SemanticType::Integer {
                family: if value.suffix().is_empty() {
                    "inferred_integer".into()
                } else {
                    value.suffix().into()
                },
            },
            syn::Lit::Float(value) => SemanticType::Float {
                family: if value.suffix().is_empty() {
                    "inferred_float".into()
                } else {
                    value.suffix().into()
                },
            },
            _ => return None,
        };
        Some(
            self.registry
                .register_semantic(semantic, value.to_token_stream().to_string()),
        )
    }

    fn reference_type(&mut self, value: &syn::ExprReference) -> Option<InterfaceType> {
        let target = self.expression_type(&value.expr)?;
        let semantic = self.registry.types.get(&target.type_id)?.0.clone();
        Some(self.registry.register_semantic(
            SemanticType::Reference {
                mutable: value.mutability.is_some(),
                lifetime: None,
                target: Box::new(semantic),
            },
            value.to_token_stream().to_string(),
        ))
    }

    fn dereference_type(&mut self, value: &syn::ExprUnary) -> Option<InterfaceType> {
        let source = self.expression_type(&value.expr)?;
        let semantic = self.registry.types.get(&source.type_id)?.0.clone();
        match semantic {
            SemanticType::Reference { target, .. } | SemanticType::Pointer { target, .. } => Some(
                self.registry
                    .register_semantic(*target, value.to_token_stream().to_string()),
            ),
            _ => None,
        }
    }

    fn tuple_expression_type(&mut self, value: &syn::ExprTuple) -> Option<InterfaceType> {
        let mut elements = Vec::new();
        for element in &value.elems {
            let interface = self.expression_type(element)?;
            elements.push(self.registry.types.get(&interface.type_id)?.0.clone());
        }
        Some(self.registry.register_semantic(
            SemanticType::Tuple { elements },
            value.to_token_stream().to_string(),
        ))
    }

    fn struct_expression_type(&mut self, value: &syn::ExprStruct) -> InterfaceType {
        let name = self
            .expand_alias(
                &value
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>(),
            )
            .join("::");
        self.registry.register_semantic(
            SemanticType::Named {
                name: name.clone(),
                arguments: Vec::new(),
            },
            name,
        )
    }

    fn field_expression_type(&mut self, value: &syn::ExprField) -> Option<InterfaceType> {
        let receiver = self.expression_type(&value.base)?;
        let owner = self.type_spelling(&receiver)?;
        self.lookup.field_type(
            self.package_name(),
            &owner,
            &value.member.to_token_stream().to_string(),
        )
    }

    fn try_expression_type(&mut self, value: &syn::ExprTry) -> Option<InterfaceType> {
        let source = self.expression_type(&value.expr)?;
        let semantic = match self.registry.types.get(&source.type_id)?.0.clone() {
            SemanticType::Result { success, .. } => *success,
            SemanticType::Option { value, .. } => *value,
            _ => return None,
        };
        Some(
            self.registry
                .register_semantic(semantic, value.to_token_stream().to_string()),
        )
    }

    fn if_expression_type(&mut self, value: &syn::ExprIf) -> Option<InterfaceType> {
        let then_type = value
            .then_branch
            .stmts
            .last()
            .and_then(|statement| match statement {
                syn::Stmt::Expr(expression, None) => self.expression_type(expression),
                _ => None,
            });
        let else_type = value
            .else_branch
            .as_ref()
            .and_then(|(_, expression)| self.expression_type(expression));
        (then_type == else_type).then_some(then_type).flatten()
    }

    fn match_expression_type(&mut self, value: &syn::ExprMatch) -> Option<InterfaceType> {
        let mut resolved = None;
        for arm in &value.arms {
            let current = self.expression_type(&arm.body)?;
            if resolved.as_ref().is_some_and(|known| known != &current) {
                return None;
            }
            resolved = Some(current);
        }
        resolved
    }

    fn type_spelling(&self, interface: &InterfaceType) -> Option<String> {
        self.type_spelling_depth(interface, 0)
    }

    fn receiver_type_reason(&self, interface: &InterfaceType) -> Option<CallResolutionReason> {
        let mut semantic = &self.registry.types.get(&interface.type_id)?.0;
        if let SemanticType::Reference { target, .. } | SemanticType::Pointer { target, .. } =
            semantic
        {
            semantic = target;
        }
        matches!(semantic, SemanticType::GenericParameter { .. })
            .then_some(CallResolutionReason::GenericReceiver)
    }

    fn type_spelling_depth(&self, interface: &InterfaceType, depth: usize) -> Option<String> {
        if depth > 8 {
            return None;
        }
        if interface.rust_spelling.contains("dyn ") {
            return Some(interface.rust_spelling.clone());
        }
        let semantic = &self.registry.types.get(&interface.type_id)?.0;
        let owner = match semantic {
            SemanticType::Reference { target, .. } | SemanticType::Pointer { target, .. } => {
                semantic_type_name(target)?
            }
            value => semantic_type_name(value)?,
        };
        if let Some(target) = self.lookup.alias_target(self.package_name(), &owner) {
            return self.type_spelling_depth(&target, depth + 1);
        }
        Some(owner)
    }

    fn call_return_type(&mut self, call: &syn::ExprCall) -> Option<InterfaceType> {
        let Expr::Path(path) = call.func.as_ref() else {
            return None;
        };
        let segments = self.expand_alias(
            &path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>(),
        );
        if let Some(last) = segments.last() {
            if last == "Some" {
                let value = self.expression_type(call.args.first()?)?;
                let semantic = self.registry.types.get(&value.type_id)?.0.clone();
                return Some(self.registry.register_semantic(
                    SemanticType::Option {
                        value: Box::new(semantic),
                    },
                    call.to_token_stream().to_string(),
                ));
            }
            if matches!(last.as_str(), "Ok" | "Err") {
                return None;
            }
        }
        let outcome = self.lookup.resolve_path(
            self.package_name(),
            &self.body.context.crate_name,
            &self.body.context.namespace,
            self.body.owner_type.as_deref(),
            &segments,
            path.qself.is_some(),
        );
        let callee = self.lookup.symbol(outcome.callee.as_deref()?)?;
        self.substitute_return(callee, call.args.iter())
    }

    fn method_return_type(&mut self, call: &syn::ExprMethodCall) -> Option<InterfaceType> {
        let receiver = self.expression_type(&call.receiver)?;
        let owner = self.type_spelling(&receiver)?;
        let outcome =
            self.lookup
                .resolve_method(self.package_name(), &owner, &call.method.to_string());
        let callee = self.lookup.symbol(outcome.callee.as_deref()?)?;
        Some(callee.return_type.clone())
    }

    fn substitute_return<'b>(
        &mut self,
        callee: &ExecutableSymbol,
        arguments: impl IntoIterator<Item = &'b Expr>,
    ) -> Option<InterfaceType> {
        let return_semantic = self
            .registry
            .types
            .get(&callee.return_type.type_id)?
            .0
            .clone();
        if matches!(&return_semantic, SemanticType::Named { name, .. } if name == "Self")
            && let Some(owner) = &callee.owner_type
        {
            return Some(self.registry.register_semantic(
                SemanticType::Named {
                    name: owner.clone(),
                    arguments: Vec::new(),
                },
                owner.clone(),
            ));
        }
        if let SemanticType::GenericParameter { name } = &return_semantic {
            for (argument, parameter) in arguments.into_iter().zip(&callee.parameters) {
                let parameter_semantic = self
                    .registry
                    .types
                    .get(&parameter.parameter_type.type_id)?
                    .0
                    .clone();
                if parameter_semantic == (SemanticType::GenericParameter { name: name.clone() }) {
                    return self.expression_type(argument);
                }
            }
        }
        Some(callee.return_type.clone())
    }

    fn endpoint_for_expression(&mut self, expression: &Expr) -> ValueEndpoint {
        let type_id = self.expression_type(expression).map(|value| value.type_id);
        ValueEndpoint::new(
            self.body.symbol.clone(),
            "expression",
            expression.to_token_stream().to_string(),
            type_id,
        )
    }

    fn transfer_to_return(&mut self, expression: &Expr, span: Span) {
        let producer = self.endpoint_for_expression(expression);
        let consumer = ValueEndpoint::new(
            self.body.symbol.clone(),
            "return",
            "return",
            Some(self.body.return_type.type_id.clone()),
        );
        let resolution = if producer.static_type.is_some() {
            TransferResolutionState::SyntaxExact
        } else {
            TransferResolutionState::TypeUnknown
        };
        self.transfers.push(make_transfer(
            ValueTransferKind::ExpressionToReturn,
            producer,
            consumer,
            resolution,
            provenance(&self.body.source_path, span, Some(self.body.symbol.clone())),
        ));
    }

    fn add_transformation(
        &mut self,
        kind: TransformationKind,
        span: Span,
        source_type: Option<String>,
        target_type: Option<String>,
    ) {
        let provenance = provenance(&self.body.source_path, span, Some(self.body.symbol.clone()));
        let id = canonical_fact_id(
            "transformation",
            &TransformationIdentity {
                symbol: &self.body.symbol,
                kind,
                provenance: &provenance,
            },
        );
        self.transformations.push(TypeTransformation {
            id,
            symbol: self.body.symbol.clone(),
            kind,
            source_type,
            target_type,
            provenance,
        });
    }

    fn raw_arguments<'b>(
        &mut self,
        arguments: impl IntoIterator<Item = &'b Expr>,
    ) -> Vec<RawArgument> {
        arguments
            .into_iter()
            .map(|argument| RawArgument {
                label: argument.to_token_stream().to_string(),
                type_id: self.expression_type(argument).map(|value| value.type_id),
                provenance: provenance(
                    &self.body.source_path,
                    argument.span(),
                    Some(self.body.symbol.clone()),
                ),
            })
            .collect()
    }

    fn direct_consumer(&self, span: Span) -> Option<ValueEndpoint> {
        self.direct_consumer
            .as_ref()
            .filter(|(key, _)| *key == SpanKey::from_span(span))
            .map(|(_, endpoint)| endpoint.clone())
    }

    fn bind_pattern_type(&mut self, pattern: &Pat, interface: &InterfaceType) {
        match pattern {
            Pat::Ident(value) => {
                self.local_types
                    .insert(value.ident.to_string(), interface.clone());
            }
            Pat::Type(value) => self.bind_pattern_type(&value.pat, interface),
            Pat::Tuple(value) => {
                let Some(SemanticType::Tuple { elements }) = self
                    .registry
                    .types
                    .get(&interface.type_id)
                    .map(|value| value.0.clone())
                else {
                    return;
                };
                for (pattern, semantic) in value.elems.iter().zip(elements) {
                    let component = self
                        .registry
                        .register_semantic(semantic, pattern.to_token_stream().to_string());
                    self.bind_pattern_type(pattern, &component);
                }
            }
            _ => {}
        }
    }

    fn structured_place(&mut self, expression: &Expr) -> (ProgramPlace, PlaceResolutionState) {
        match expression {
            Expr::Paren(value) => self.structured_place(&value.expr),
            Expr::Group(value) => self.structured_place(&value.expr),
            Expr::Path(value) if value.path.segments.len() == 1 => {
                let name = value.path.segments[0].ident.to_string();
                let static_type = self
                    .expression_type(expression)
                    .map(|interface| interface.type_id);
                let resolution = if static_type.is_some() {
                    PlaceResolutionState::ResolvedExact
                } else {
                    PlaceResolutionState::TypeUnknown
                };
                (ProgramPlace::Binding { name, static_type }, resolution)
            }
            Expr::Field(value) => {
                let (base, base_resolution) = self.structured_place(&value.base);
                let base_interface = self.expression_type(&value.base);
                let owner = base_interface
                    .as_ref()
                    .and_then(|interface| self.type_spelling(interface));
                let field_type = self.expression_type(expression).map(|value| value.type_id);
                match &value.member {
                    syn::Member::Named(name) => {
                        let nominal_owner = owner.as_ref().and_then(|name| {
                            self.lookup
                                .nominal_id(self.package_name(), name)
                                .map(str::to_owned)
                        });
                        let resolution = if nominal_owner.is_some() && field_type.is_some() {
                            PlaceResolutionState::ResolvedExact
                        } else if base_resolution == PlaceResolutionState::Unsupported {
                            PlaceResolutionState::Unsupported
                        } else {
                            PlaceResolutionState::TypeUnknown
                        };
                        (
                            ProgramPlace::Field {
                                base: Box::new(base),
                                nominal_owner,
                                field: name.to_string(),
                                static_type: field_type,
                            },
                            resolution,
                        )
                    }
                    syn::Member::Unnamed(index) => {
                        let resolution = if field_type.is_some() {
                            PlaceResolutionState::ResolvedExact
                        } else {
                            PlaceResolutionState::TypeUnknown
                        };
                        (
                            ProgramPlace::TupleField {
                                base: Box::new(base),
                                position: usize::try_from(index.index).unwrap_or(usize::MAX),
                                static_type: field_type,
                            },
                            resolution,
                        )
                    }
                }
            }
            Expr::Unary(value) if matches!(value.op, syn::UnOp::Deref(_)) => {
                let (base, _) = self.structured_place(&value.expr);
                (
                    ProgramPlace::Dereference {
                        base: Box::new(base),
                        static_type: self.expression_type(expression).map(|value| value.type_id),
                    },
                    PlaceResolutionState::AliasUnknown,
                )
            }
            _ => (
                ProgramPlace::Unsupported {
                    rust_spelling: expression.to_token_stream().to_string(),
                },
                PlaceResolutionState::Unsupported,
            ),
        }
    }

    fn add_mutation(&mut self, target: &Expr, value: &Expr, kind: MutationKind, span: Span) {
        let (target, resolution) = self.structured_place(target);
        let provenance = provenance(&self.body.source_path, span, Some(self.body.symbol.clone()));
        let value_type = self
            .expression_type(value)
            .map(|interface| interface.type_id);
        let mutation_kind = if matches!(
            target,
            ProgramPlace::Field { .. } | ProgramPlace::TupleField { .. }
        ) {
            MutationKind::MutableFieldUpdate
        } else {
            kind
        };
        let id = canonical_fact_id(
            "mutation",
            &MutationIdentity {
                symbol: &self.body.symbol,
                target: &target,
                mutation_kind,
                provenance: &provenance,
            },
        );
        self.mutations.push(ProgramMutation {
            id,
            symbol: self.body.symbol.clone(),
            target,
            mutation_kind,
            value: lower_expression(value),
            value_type,
            resolution,
            provenance,
        });
    }
}

#[derive(Serialize)]
struct MutationIdentity<'a> {
    symbol: &'a str,
    target: &'a ProgramPlace,
    mutation_kind: MutationKind,
    provenance: &'a ProgramProvenance,
}

#[derive(Serialize)]
struct StateReadIdentity<'a> {
    symbol: &'a str,
    place: &'a ProgramPlace,
    provenance: &'a ProgramProvenance,
}

impl<'ast> Visit<'ast> for BodyAnalyzer<'_> {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        let name = pattern_name(&local.pat);
        let declared_type = match &local.pat {
            Pat::Type(value) => Some(self.registry.register_with_aliases(
                &value.ty,
                &BTreeSet::new(),
                &self.body.aliases,
            )),
            _ => None,
        };
        if let Some(binding) = simple_pattern_name(&local.pat)
            && let Some(value) = &declared_type
        {
            self.local_types.insert(binding, value.clone());
        }
        if !matches!(local.pat, Pat::Ident(_) | Pat::Type(_)) {
            self.add_transformation(
                TransformationKind::Destructuring,
                local.pat.span(),
                None,
                declared_type.as_ref().map(|value| value.type_id.clone()),
            );
        }
        if let Some(initializer) = &local.init {
            let inferred = declared_type.or_else(|| self.expression_type(&initializer.expr));
            if let Some(binding) = simple_pattern_name(&local.pat)
                && let Some(value) = &inferred
            {
                self.local_types.insert(binding, value.clone());
            }
            if let Some(value) = &inferred {
                self.bind_pattern_type(&local.pat, value);
            }
            let consumer = ValueEndpoint::new(
                self.body.symbol.clone(),
                "binding",
                name,
                inferred.as_ref().map(|value| value.type_id.clone()),
            );
            let producer = self.endpoint_for_expression(&initializer.expr);
            let resolution = if producer.static_type.is_some() || consumer.static_type.is_some() {
                TransferResolutionState::SyntaxExact
            } else {
                TransferResolutionState::TypeUnknown
            };
            self.transfers.push(make_transfer(
                ValueTransferKind::ExpressionToBinding,
                producer,
                consumer.clone(),
                resolution,
                provenance(
                    &self.body.source_path,
                    initializer.expr.span(),
                    Some(self.body.symbol.clone()),
                ),
            ));
            self.direct_consumer = Some((SpanKey::from_span(initializer.expr.span()), consumer));
            self.visit_expr(&initializer.expr);
            self.direct_consumer = None;
        }
    }

    fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
        self.add_mutation(
            &assignment.left,
            &assignment.right,
            MutationKind::Assignment,
            assignment.span(),
        );
        let inferred_assignment = self.expression_type(&assignment.right);
        if let Expr::Path(path) = assignment.left.as_ref()
            && path.path.segments.len() == 1
            && let Some(value) = &inferred_assignment
        {
            self.local_types
                .insert(path.path.segments[0].ident.to_string(), value.clone());
        }
        let consumer = ValueEndpoint::new(
            self.body.symbol.clone(),
            "place",
            assignment.left.to_token_stream().to_string(),
            self.expression_type(&assignment.left)
                .map(|value| value.type_id),
        );
        let producer = self.endpoint_for_expression(&assignment.right);
        self.transfers.push(make_transfer(
            ValueTransferKind::Assignment,
            producer,
            consumer.clone(),
            TransferResolutionState::TypeUnknown,
            provenance(
                &self.body.source_path,
                assignment.span(),
                Some(self.body.symbol.clone()),
            ),
        ));
        self.write_target = true;
        self.visit_expr(&assignment.left);
        self.write_target = false;
        self.direct_consumer = Some((SpanKey::from_span(assignment.right.span()), consumer));
        self.visit_expr(&assignment.right);
        self.direct_consumer = None;
    }

    fn visit_expr_binary(&mut self, expression: &'ast syn::ExprBinary) {
        if matches!(
            expression.op,
            syn::BinOp::AddAssign(_)
                | syn::BinOp::SubAssign(_)
                | syn::BinOp::MulAssign(_)
                | syn::BinOp::DivAssign(_)
                | syn::BinOp::RemAssign(_)
                | syn::BinOp::BitXorAssign(_)
                | syn::BinOp::BitAndAssign(_)
                | syn::BinOp::BitOrAssign(_)
                | syn::BinOp::ShlAssign(_)
                | syn::BinOp::ShrAssign(_)
        ) {
            self.add_mutation(
                &expression.left,
                &expression.right,
                MutationKind::CompoundAssignment,
                expression.span(),
            );
        }
        visit::visit_expr_binary(self, expression);
    }

    fn visit_expr_field(&mut self, expression: &'ast syn::ExprField) {
        if !self.write_target {
            let (place, resolution) = self.structured_place(&Expr::Field(expression.clone()));
            let provenance = provenance(
                &self.body.source_path,
                expression.span(),
                Some(self.body.symbol.clone()),
            );
            let id = canonical_fact_id(
                "state_read",
                &StateReadIdentity {
                    symbol: &self.body.symbol,
                    place: &place,
                    provenance: &provenance,
                },
            );
            self.state_reads.push(StateRead {
                id,
                symbol: self.body.symbol.clone(),
                place,
                resolution,
                provenance,
            });
        }
        visit::visit_expr_field(self, expression);
    }

    fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
        if let Some(value) = &expression.expr {
            self.transfer_to_return(value, expression.span());
            self.visit_expr(value);
        }
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let reference = call.func.to_token_stream().to_string();
        let target = match call.func.as_ref() {
            Expr::Path(path) => {
                let segments = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>();
                let is_callable_binding = segments.len() == 1
                    && self
                        .local_types
                        .get(&segments[0])
                        .and_then(|value| self.registry.types.get(&value.type_id))
                        .is_some_and(|(semantic, _)| {
                            matches!(semantic, SemanticType::Function { .. })
                        });
                if is_callable_binding {
                    RawCallTarget::Dynamic
                } else {
                    RawCallTarget::Path {
                        segments: self.expand_alias(&segments),
                        qualified_self: path.qself.is_some(),
                    }
                }
            }
            _ => RawCallTarget::Dynamic,
        };
        let semantic_constructor = if let RawCallTarget::Path { segments, .. } = &target
            && let Some(last) = segments.last()
        {
            match last.as_str() {
                "Some" => {
                    self.add_transformation(
                        TransformationKind::OptionTransition,
                        call.span(),
                        None,
                        None,
                    );
                    true
                }
                "Ok" | "Err" => {
                    self.add_transformation(
                        TransformationKind::ResultTransition,
                        call.span(),
                        None,
                        None,
                    );
                    true
                }
                "from" => {
                    self.add_transformation(
                        TransformationKind::ConversionCall,
                        call.span(),
                        None,
                        None,
                    );
                    false
                }
                _ => false,
            }
        } else {
            false
        };
        let arguments = self.raw_arguments(call.args.iter());
        if !semantic_constructor {
            self.raw_calls.push(RawCall {
                caller: self.body.symbol.clone(),
                package: self.package_name().into(),
                crate_name: self.body.context.crate_name.clone(),
                namespace: self.body.context.namespace.clone(),
                owner_type: self.body.owner_type.clone(),
                target,
                reference: reference.clone(),
                arguments,
                consumer: self.direct_consumer(call.span()),
                evidence: CallSiteEvidence::new(
                    reference,
                    call.args.len(),
                    provenance(
                        &self.body.source_path,
                        call.span(),
                        Some(self.body.symbol.clone()),
                    ),
                ),
            });
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let receiver_interface = self.expression_type(&call.receiver);
        let receiver_type = receiver_interface
            .as_ref()
            .and_then(|value| self.type_spelling(value))
            .or_else(|| {
                matches!(call.receiver.as_ref(), Expr::Path(path) if path.path.is_ident("self"))
                    .then(|| self.body.owner_type.clone())
                    .flatten()
            });
        let receiver_reason = receiver_interface
            .as_ref()
            .and_then(|value| self.receiver_type_reason(value))
            .or_else(|| {
                receiver_type
                    .is_none()
                    .then_some(if is_deref_expression(&call.receiver) {
                        CallResolutionReason::UnsupportedDeref
                    } else {
                        CallResolutionReason::UnknownReceiverType
                    })
            });
        let method = call.method.to_string();
        if matches!(method.as_str(), "into" | "try_into" | "from") {
            self.add_transformation(TransformationKind::ConversionCall, call.span(), None, None);
        }
        let reference = call.to_token_stream().to_string();
        let arguments = self.raw_arguments(call.args.iter());
        let receiver_place = self.structured_place(&call.receiver).0;
        self.raw_calls.push(RawCall {
            caller: self.body.symbol.clone(),
            package: self.package_name().into(),
            crate_name: self.body.context.crate_name.clone(),
            namespace: self.body.context.namespace.clone(),
            owner_type: self.body.owner_type.clone(),
            target: RawCallTarget::Method {
                method,
                receiver_type,
                receiver_display: call.receiver.to_token_stream().to_string(),
                receiver_reason,
            },
            reference: reference.clone(),
            arguments,
            consumer: self.direct_consumer(call.span()),
            evidence: CallSiteEvidence::new(
                reference,
                call.args.len(),
                provenance(
                    &self.body.source_path,
                    call.span(),
                    Some(self.body.symbol.clone()),
                ),
            )
            .with_receiver(receiver_place),
        });
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_macro(&mut self, expression: &'ast syn::ExprMacro) {
        let reference = expression.mac.path.to_token_stream().to_string();
        self.raw_calls.push(RawCall {
            caller: self.body.symbol.clone(),
            package: self.package_name().into(),
            crate_name: self.body.context.crate_name.clone(),
            namespace: self.body.context.namespace.clone(),
            owner_type: self.body.owner_type.clone(),
            target: RawCallTarget::Macro,
            reference: reference.clone(),
            arguments: Vec::new(),
            consumer: None,
            evidence: CallSiteEvidence::new(
                reference,
                0,
                provenance(
                    &self.body.source_path,
                    expression.span(),
                    Some(self.body.symbol.clone()),
                ),
            ),
        });
    }

    fn visit_expr_cast(&mut self, expression: &'ast syn::ExprCast) {
        let source_type = self
            .expression_type(&expression.expr)
            .map(|value| value.type_id);
        let target = self.registry.register(&expression.ty, &BTreeSet::new());
        self.add_transformation(
            TransformationKind::Cast,
            expression.span(),
            source_type,
            Some(target.type_id),
        );
        visit::visit_expr_cast(self, expression);
    }

    fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
        let source_type = self
            .expression_type(&expression.expr)
            .map(|value| value.type_id);
        self.add_transformation(
            TransformationKind::ResultTransition,
            expression.span(),
            source_type,
            None,
        );
        visit::visit_expr_try(self, expression);
    }

    fn visit_expr_reference(&mut self, expression: &'ast syn::ExprReference) {
        let source_type = self
            .expression_type(&expression.expr)
            .map(|value| value.type_id);
        let target_type = self
            .expression_type(&Expr::Reference(expression.clone()))
            .map(|value| value.type_id);
        self.add_transformation(
            TransformationKind::ReferenceTransition,
            expression.span(),
            source_type,
            target_type,
        );
        visit::visit_expr_reference(self, expression);
    }
}

impl BodyAnalyzer<'_> {
    fn package_name(&self) -> &str {
        &self.body.context.package_name
    }
}

fn is_deref_expression(expression: &Expr) -> bool {
    match expression {
        Expr::Paren(value) => is_deref_expression(&value.expr),
        Expr::Group(value) => is_deref_expression(&value.expr),
        Expr::Unary(value) => matches!(value.op, syn::UnOp::Deref(_)),
        _ => false,
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct CallGroupKey {
    caller: String,
    state: CallResolutionState,
    authority: ResolutionAuthority,
    reason: Option<CallResolutionReason>,
    callee: Option<String>,
    boundary_target_module: Option<String>,
    external_target: Option<String>,
    candidates: Vec<String>,
    unresolved_reference: Option<String>,
}

fn resolve_calls(
    raw_calls: Vec<RawCall>,
    lookup: &SymbolLookup,
    transfers: &mut Vec<ValueTransfer>,
    registry: &mut TypeRegistry,
) -> Vec<ProgramCall> {
    let mut grouped = BTreeMap::<CallGroupKey, Vec<CallSiteEvidence>>::new();
    for call in raw_calls {
        let mut outcome = resolve_call(&call, lookup);
        outcome.candidates.sort();
        outcome.candidates.dedup();
        if let Some(callee_id) = &outcome.callee
            && let Some(callee) = lookup.symbol(callee_id)
        {
            add_interprocedural_transfers(&call, callee, transfers, registry, &outcome);
        }
        let unresolved_reference = matches!(
            outcome.state,
            CallResolutionState::DynamicDispatch
                | CallResolutionState::Unresolved
                | CallResolutionState::Unsupported
                | CallResolutionState::Invalid
        )
        .then(|| call.reference.clone());
        grouped
            .entry(CallGroupKey {
                caller: call.caller,
                state: outcome.state,
                authority: outcome.authority,
                reason: outcome.reason,
                callee: outcome.callee,
                boundary_target_module: outcome.boundary_target_module,
                external_target: outcome.external_target,
                candidates: outcome.candidates,
                unresolved_reference,
            })
            .or_default()
            .push(call.evidence);
    }
    grouped
        .into_iter()
        .map(|(key, mut evidence)| {
            evidence.sort();
            evidence.dedup();
            ProgramCall {
                id: canonical_fact_id("call", &key),
                caller: key.caller,
                state: key.state,
                authority: key.authority,
                reason: key.reason,
                callee: key.callee,
                boundary_target_module: key.boundary_target_module,
                external_target: key.external_target,
                candidate_callees: key.candidates,
                evidence,
            }
        })
        .collect()
}

fn resolve_call(call: &RawCall, lookup: &SymbolLookup) -> CallOutcome {
    let mut outcome = match &call.target {
        RawCallTarget::Path {
            segments,
            qualified_self,
        } => lookup.resolve_path(
            &call.package,
            &call.crate_name,
            &call.namespace,
            call.owner_type.as_deref(),
            segments,
            *qualified_self,
        ),
        RawCallTarget::Method {
            method,
            receiver_type,
            receiver_display,
            receiver_reason,
        } => {
            if *receiver_reason == Some(CallResolutionReason::GenericReceiver) {
                return CallOutcome::unresolved()
                    .with_reason(CallResolutionReason::GenericReceiver);
            }
            let owner = receiver_type.as_deref().or_else(|| {
                (receiver_display == "self")
                    .then_some(call.owner_type.as_deref())
                    .flatten()
            });
            if owner.is_some_and(|value| value.contains("dyn ")) {
                CallOutcome::dynamic(Vec::new())
                    .with_reason(CallResolutionReason::TraitObjectDispatch)
            } else if let Some(owner) = owner {
                let mut outcome = lookup.resolve_method(&call.package, owner, method);
                if outcome.state == CallResolutionState::ResolvedStatic {
                    outcome.authority = ResolutionAuthority::TypeDirectedExact;
                    outcome
                } else if outcome.reason == Some(CallResolutionReason::AmbiguousLocalMethod) {
                    outcome
                } else if is_standard_type(owner)
                    || (!lookup.is_local_nominal(&call.package, owner)
                        && starts_type_name(owner)
                        && simple_type_name(owner).len() > 1)
                {
                    CallOutcome::external(format!(
                        "rust_method::{}::{method}",
                        simple_type_name(owner)
                    ))
                } else {
                    CallOutcome::unresolved().with_reason(if simple_type_name(owner).len() <= 2 {
                        CallResolutionReason::GenericReceiver
                    } else {
                        CallResolutionReason::UnresolvedTraitSelection
                    })
                }
            } else {
                CallOutcome::unresolved().with_reason(
                    receiver_reason.unwrap_or(CallResolutionReason::UnknownReceiverType),
                )
            }
        }
        RawCallTarget::Dynamic => {
            CallOutcome::dynamic(Vec::new()).with_reason(CallResolutionReason::FunctionPointer)
        }
        RawCallTarget::Macro => {
            CallOutcome::unsupported().with_reason(CallResolutionReason::MacroGenerated)
        }
    };
    if outcome.state == CallResolutionState::ResolvedStatic
        && let Some(callee) = outcome
            .callee
            .as_deref()
            .and_then(|callee| lookup.symbol(callee))
        && callee.package == call.package
        && callee.crate_name != call.crate_name
        && let Some(package) = lookup.packages.get(&call.package)
        && callee.crate_name == package.lib_name
    {
        outcome
            .boundary_target_module
            .clone_from(&package.facade_owner);
    }
    outcome
}

fn add_interprocedural_transfers(
    call: &RawCall,
    callee: &ExecutableSymbol,
    transfers: &mut Vec<ValueTransfer>,
    _registry: &mut TypeRegistry,
    outcome: &CallOutcome,
) {
    for (argument, parameter) in call.arguments.iter().zip(&callee.parameters) {
        transfers.push(make_transfer(
            ValueTransferKind::ArgumentToParameter,
            ValueEndpoint::new(
                call.caller.clone(),
                "argument",
                argument.label.clone(),
                argument.type_id.clone(),
            ),
            ValueEndpoint::new(
                callee.id.clone(),
                "parameter",
                parameter.name.clone(),
                Some(parameter.parameter_type.type_id.clone()),
            ),
            TransferResolutionState::ResolvedStaticCall,
            argument.provenance.clone(),
        ));
    }
    if let Some(consumer) = &call.consumer {
        transfers.push(make_transfer(
            ValueTransferKind::ReturnToConsumer,
            ValueEndpoint::new(
                callee.id.clone(),
                "return",
                "return",
                Some(callee.return_type.type_id.clone()),
            ),
            consumer.clone(),
            TransferResolutionState::ResolvedStaticCall,
            call.evidence.provenance.clone(),
        ));
    }
    debug_assert_eq!(outcome.state, CallResolutionState::ResolvedStatic);
}
