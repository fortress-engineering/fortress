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

use crate::implementation_observation::ModuleTerritory;

use super::{
    CallResolutionState, CallSiteEvidence, ExecutableSymbol, ExecutableSymbolKind, InterfaceType,
    ProgramCall, ProgramPackage, ProgramParameter, ProgramProvenance, ProgramReceiver,
    ProgramSemanticError, ProgramSemanticInput, ProgramSourceInput, ProgramSourceLocation,
    ProgramTarget, ProgramType, RUST_PROGRAM_ANALYZER_ID, ResolutionAuthority, RustProgramFacts,
    SemanticType, SymbolBodyState, SymbolClassification, SymbolQualifiers, SymbolVisibility,
    TransferResolutionState, TransformationKind, TypeResolution, TypeTransformation, ValueEndpoint,
    ValueTransfer, ValueTransferKind, canonical_fact_id,
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

pub(super) fn analyze(
    input: &ProgramSemanticInput,
) -> Result<RustProgramFacts, ProgramSemanticError> {
    let files = verified_files(input)?;
    let source_inputs = semantic_source_inputs(&files);
    let source_identity = semantic_source_identity(&source_inputs);
    let mut packages = parse_packages(&files)?;
    resolve_dependencies(&mut packages);
    let source_owners = source_owners(input.observation().modules(), files.keys())?;
    let source_contexts = build_source_contexts(&packages, &files)?;
    let source_files = source_contexts.len();
    let package_by_manifest: BTreeMap<&str, &CargoPackage> = packages
        .iter()
        .map(|package| (package.manifest_path.as_str(), package))
        .collect();
    let mut registry = TypeRegistry::default();
    let mut symbols = Vec::new();
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
                bodies: &mut bodies,
                transfers: &mut parameter_transfers,
                reexports: &mut reexports,
            };
            collection.collect_items(&syntax.items, &context.namespace, &BTreeMap::new());
        }
    }
    symbols.sort();
    symbols.dedup();
    bodies.sort_by(|left, right| left.symbol.cmp(&right.symbol));
    bodies.dedup_by(|left, right| left.symbol == right.symbol);
    let lookup = SymbolLookup::new(&symbols, &packages, &source_owners, reexports);
    let mut raw_calls = Vec::new();
    let mut value_transfers = parameter_transfers;
    let mut transformations = Vec::new();
    for body in &bodies {
        BodyAnalyzer::new(
            body,
            &mut registry,
            &mut raw_calls,
            &mut value_transfers,
            &mut transformations,
        )
        .analyze();
    }
    let calls = resolve_calls(raw_calls, &lookup, &mut value_transfers, &mut registry);
    value_transfers.sort();
    value_transfers.dedup();
    transformations.sort();
    transformations.dedup();
    Ok(RustProgramFacts {
        source_identity,
        source_inputs,
        source_files,
        packages: package_facts(&packages),
        symbols,
        types: registry.finish(),
        calls,
        value_transfers,
        transformations,
    })
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
            Some(join_path(
                &manifest_dir,
                target.path.as_deref().unwrap_or("src/lib.rs"),
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
            root: join_path(&manifest_dir, path),
            kind: "binary".into(),
        })
    }));
    targets.extend(document.test.iter().filter_map(|target| {
        target.path.as_ref().map(|path| CargoTarget {
            crate_name: rust_crate_name(target.name.as_deref().unwrap_or("test")),
            root: join_path(&manifest_dir, path),
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

fn source_owners<'a>(
    modules: &'a [ModuleTerritory],
    paths: impl Iterator<Item = &'a String>,
) -> Result<BTreeMap<String, String>, ProgramSemanticError> {
    let mut owners = BTreeMap::new();
    for path in paths.filter(|path| is_rust_path(path)) {
        let owner = modules
            .iter()
            .filter(|module| contains_path(module.path(), path))
            .max_by_key(|module| module.path().len())
            .ok_or_else(|| ProgramSemanticError::MissingSourceOwner(path.clone()))?;
        let relative = if owner.path().is_empty() {
            path.as_str()
        } else {
            path.strip_prefix(&format!("{}/", owner.path()))
                .unwrap_or(path)
        };
        if !relative.starts_with("code/") || relative["code/".len()..].contains('/') {
            return Err(ProgramSemanticError::MissingSourceOwner(path.clone()));
        }
        owners.insert(path.clone(), owner.id().into());
    }
    Ok(owners)
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
    collect_modules(&syntax.items, path, namespace, &mut queue);
    while let Some(module) = queue.pop_front() {
        match module {
            DiscoveredModule::Inline { namespace, items } => {
                collect_modules(&items, path, &namespace, &mut queue);
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
                declared_path: module_path_attribute(&module.attrs)
                    .unwrap_or_else(|| default_module_path(source_path, &module.ident.to_string())),
            });
        }
    }
}

fn module_path_attribute(attributes: &[Attribute]) -> Option<String> {
    attributes.iter().find_map(|attribute| {
        if !attribute.path().is_ident("path") {
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

fn default_module_path(source_path: &str, module: &str) -> String {
    let directory = parent_path(source_path);
    let filename = source_path.rsplit('/').next().unwrap_or(source_path);
    if matches!(filename, "lib.rs" | "main.rs" | "mod.rs") {
        join_path(&directory, &format!("{module}.rs"))
    } else {
        let stem = filename.strip_suffix(".rs").unwrap_or(filename);
        join_path(&directory, &format!("{stem}/{module}.rs"))
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
    .find(|candidate| files.contains_key(candidate))
}

struct SymbolCollection<'a> {
    package: &'a CargoPackage,
    context: &'a SourceContext,
    owner: &'a str,
    classification: SymbolClassification,
    source_path: &'a str,
    registry: &'a mut TypeRegistry,
    symbols: &'a mut Vec<ExecutableSymbol>,
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
        let mut aliases = inherited_aliases.clone();
        for item in items {
            if let Item::Use(item_use) = item {
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
        }
        for item in items {
            match item {
                Item::Fn(function) => self.add_function(
                    namespace,
                    &function.sig,
                    &function.vis,
                    ExecutableSymbolKind::FreeFunction,
                    None,
                    None,
                    Some(function.block.as_ref().clone()),
                    &aliases,
                    &BTreeSet::new(),
                ),
                Item::Impl(item_impl) => {
                    let owner_type = item_impl.self_ty.to_token_stream().to_string();
                    let owner_trait = item_impl
                        .trait_
                        .as_ref()
                        .map(|(_, path, _)| path.to_token_stream().to_string());
                    let impl_generics = generic_names(&item_impl.generics.params);
                    for impl_item in &item_impl.items {
                        let ImplItem::Fn(function) = impl_item else {
                            continue;
                        };
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
                            Some(owner_type.clone()),
                            owner_trait.clone(),
                            Some(function.block.clone()),
                            &aliases,
                            &impl_generics,
                        );
                    }
                }
                Item::Trait(item_trait) => {
                    let owner_trait = item_trait.ident.to_string();
                    let trait_generics = generic_names(&item_trait.generics.params);
                    for trait_item in &item_trait.items {
                        let TraitItem::Fn(function) = trait_item else {
                            continue;
                        };
                        self.add_function(
                            namespace,
                            &function.sig,
                            &Visibility::Public(syn::token::Pub::default()),
                            ExecutableSymbolKind::TraitMethodDeclaration,
                            None,
                            Some(owner_trait.clone()),
                            function.default.clone(),
                            &aliases,
                            &trait_generics,
                        );
                    }
                }
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
    ) {
        let FunctionInterface {
            parameters,
            parameter_types,
            return_type,
            receiver,
            generic_parameters,
            lifetimes,
        } = self.function_interface(signature, surrounding_generics);
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
                symbol: id,
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
    }

    fn function_interface(
        &mut self,
        signature: &Signature,
        surrounding_generics: &BTreeSet<String>,
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
                    let explicit_type = value
                        .colon_token
                        .is_some()
                        .then(|| self.registry.register(&value.ty, &generics));
                    receiver = Some(ProgramReceiver::new(
                        value.mutability.is_some(),
                        value.reference.is_some(),
                        explicit_type,
                    ));
                }
                FnArg::Typed(value) => {
                    let position = parameters.len();
                    let name = pattern_name(&value.pat);
                    let parameter_type = self.registry.register(&value.ty, &generics);
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
            ReturnType::Type(_, output) => self.registry.register(output, &generics),
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

fn contains_path(module_path: &str, path: &str) -> bool {
    module_path.is_empty()
        || path == module_path
        || path
            .strip_prefix(module_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
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
}

impl SymbolLookup {
    fn new(
        symbols: &[ExecutableSymbol],
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
        Self {
            path_to_symbols,
            methods,
            symbols: symbols
                .iter()
                .map(|symbol| (symbol.id.clone(), symbol.clone()))
                .collect(),
            packages: package_lookup,
            reexports,
        }
    }

    fn symbol(&self, id: &str) -> Option<&ExecutableSymbol> {
        self.symbols.get(id)
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
            Ordering::Greater => CallOutcome::dynamic(candidates),
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
        let key = (package.into(), simple_type_name(owner), method.into());
        let candidates = self.methods.get(&key).cloned().unwrap_or_default();
        match candidates.as_slice() {
            [callee] => CallOutcome::resolved(callee.clone(), None),
            [] => CallOutcome::unresolved(),
            _ => CallOutcome::dynamic(candidates),
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
            callee: Some(callee),
            boundary_target_module,
            external_target: None,
            candidates: Vec::new(),
        }
    }

    fn external(target: String) -> Self {
        Self {
            state: CallResolutionState::External,
            authority: ResolutionAuthority::CargoManifest,
            callee: None,
            boundary_target_module: None,
            external_target: Some(target),
            candidates: Vec::new(),
        }
    }

    fn dynamic(candidates: Vec<String>) -> Self {
        Self {
            state: CallResolutionState::DynamicDispatch,
            authority: ResolutionAuthority::Conservative,
            callee: None,
            boundary_target_module: None,
            external_target: None,
            candidates,
        }
    }

    fn unresolved() -> Self {
        Self {
            state: CallResolutionState::Unresolved,
            authority: ResolutionAuthority::Conservative,
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
            callee: None,
            boundary_target_module: None,
            external_target: None,
            candidates: Vec::new(),
        }
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
    registry: &'a mut TypeRegistry,
    raw_calls: &'a mut Vec<RawCall>,
    transfers: &'a mut Vec<ValueTransfer>,
    transformations: &'a mut Vec<TypeTransformation>,
    local_types: BTreeMap<String, InterfaceType>,
    direct_consumer: Option<(SpanKey, ValueEndpoint)>,
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
    fn new(
        body: &'a BodyFact,
        registry: &'a mut TypeRegistry,
        raw_calls: &'a mut Vec<RawCall>,
        transfers: &'a mut Vec<ValueTransfer>,
        transformations: &'a mut Vec<TypeTransformation>,
    ) -> Self {
        Self {
            body,
            registry,
            raw_calls,
            transfers,
            transformations,
            local_types: body.parameter_types.clone(),
            direct_consumer: None,
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
            Expr::Path(path) if path.path.segments.len() == 1 => self
                .local_types
                .get(&path.path.segments[0].ident.to_string())
                .cloned(),
            Expr::Lit(literal) => match &literal.lit {
                syn::Lit::Bool(_) => {
                    Some(self.registry.register_semantic(SemanticType::Bool, "bool"))
                }
                syn::Lit::Char(_) => {
                    Some(self.registry.register_semantic(SemanticType::Char, "char"))
                }
                syn::Lit::Str(_) => Some(self.registry.register_semantic(
                    SemanticType::Reference {
                        mutable: false,
                        lifetime: Some("'static".into()),
                        target: Box::new(SemanticType::String {
                            representation: "str".into(),
                        }),
                    },
                    "&'static str",
                )),
                syn::Lit::Int(value) => Some(self.registry.register_semantic(
                    SemanticType::Integer {
                        family: if value.suffix().is_empty() {
                            "inferred_integer".into()
                        } else {
                            value.suffix().into()
                        },
                    },
                    value.to_token_stream().to_string(),
                )),
                syn::Lit::Float(value) => Some(self.registry.register_semantic(
                    SemanticType::Float {
                        family: if value.suffix().is_empty() {
                            "inferred_float".into()
                        } else {
                            value.suffix().into()
                        },
                    },
                    value.to_token_stream().to_string(),
                )),
                _ => None,
            },
            Expr::Reference(reference) => {
                let target = self.expression_type(&reference.expr)?;
                let semantic = self
                    .registry
                    .types
                    .get(&target.type_id)
                    .map(|(semantic, _)| semantic.clone())?;
                Some(self.registry.register_semantic(
                    SemanticType::Reference {
                        mutable: reference.mutability.is_some(),
                        lifetime: None,
                        target: Box::new(semantic),
                    },
                    reference.to_token_stream().to_string(),
                ))
            }
            _ => None,
        }
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
}

impl<'ast> Visit<'ast> for BodyAnalyzer<'_> {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        let name = pattern_name(&local.pat);
        let declared_type = match &local.pat {
            Pat::Type(value) => Some(self.registry.register(&value.ty, &BTreeSet::new())),
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
        self.visit_expr(&assignment.left);
        self.direct_consumer = Some((SpanKey::from_span(assignment.right.span()), consumer));
        self.visit_expr(&assignment.right);
        self.direct_consumer = None;
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
        if let RawCallTarget::Path { segments, .. } = &target
            && let Some(last) = segments.last()
        {
            match last.as_str() {
                "Some" => self.add_transformation(
                    TransformationKind::OptionTransition,
                    call.span(),
                    None,
                    None,
                ),
                "Ok" | "Err" => self.add_transformation(
                    TransformationKind::ResultTransition,
                    call.span(),
                    None,
                    None,
                ),
                "from" => self.add_transformation(
                    TransformationKind::ConversionCall,
                    call.span(),
                    None,
                    None,
                ),
                _ => {}
            }
        }
        let arguments = self.raw_arguments(call.args.iter());
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
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let receiver_type = self
            .expression_type(&call.receiver)
            .map(|value| value.rust_spelling)
            .or_else(|| {
                matches!(call.receiver.as_ref(), Expr::Path(path) if path.path.is_ident("self"))
                    .then(|| self.body.owner_type.clone())
                    .flatten()
            });
        let method = call.method.to_string();
        if matches!(method.as_str(), "into" | "try_into" | "from") {
            self.add_transformation(TransformationKind::ConversionCall, call.span(), None, None);
        }
        let reference = call.to_token_stream().to_string();
        let arguments = self.raw_arguments(call.args.iter());
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
            ),
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct CallGroupKey {
    caller: String,
    state: CallResolutionState,
    authority: ResolutionAuthority,
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
        } => {
            let owner = receiver_type.as_deref().or_else(|| {
                (receiver_display == "self")
                    .then_some(call.owner_type.as_deref())
                    .flatten()
            });
            if owner.is_some_and(|value| value.contains("dyn ")) {
                CallOutcome::dynamic(Vec::new())
            } else if let Some(owner) = owner {
                let outcome = lookup.resolve_method(&call.package, owner, method);
                if outcome.state == CallResolutionState::ResolvedStatic {
                    outcome
                } else if is_standard_type(owner) {
                    CallOutcome::external(format!(
                        "rust_method::{}::{method}",
                        simple_type_name(owner)
                    ))
                } else {
                    CallOutcome::unresolved()
                }
            } else {
                CallOutcome::unresolved()
            }
        }
        RawCallTarget::Dynamic => CallOutcome::dynamic(Vec::new()),
        RawCallTarget::Macro => CallOutcome::unsupported(),
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
