//! Deterministic structural Rust dependency observation.

use std::collections::{BTreeMap, VecDeque};

use proc_macro2::Span;
use serde::Deserialize;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Attribute, ItemUse, Path, UseTree};

use super::{
    Conditionality, ImplementationObservation, ImplementationObservationError,
    ImplementationObservationInput, ModuleTerritory, ObservationIssue, ObservationIssueKind,
    ObservationProvenance, ObservedImplementation, RUST_LANGUAGE_ID, ResolutionStatus,
    SourceLocation, TargetClassification,
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

#[derive(Clone)]
struct CargoTarget {
    root: String,
    kind: TargetKind,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TargetKind {
    Library,
    Other,
}

#[derive(Clone)]
enum DependencyResolution {
    WorkspacePackage(String),
    External(String),
}

#[derive(Clone)]
struct NamespaceNode {
    source_path: String,
    owner: String,
}

#[derive(Default)]
struct PackageNamespaces {
    by_target: BTreeMap<String, BTreeMap<Vec<String>, NamespaceNode>>,
    library: BTreeMap<Vec<String>, NamespaceNode>,
}

#[derive(Clone)]
struct SourceContext {
    package_manifest: String,
    target_root: String,
    namespace: Vec<String>,
}

#[derive(Clone)]
struct CollectedReference {
    path: Vec<String>,
    display: String,
    span: Span,
    conditionality: Conditionality,
}

/// Analyzes Rust source and Cargo structure without consulting declared CCG edges.
///
/// # Errors
///
/// Returns an error when supplied bytes do not match their snapshot identity or
/// when supported Cargo/Rust syntax cannot be parsed.
pub fn observe_rust_implementation(
    input: &ImplementationObservationInput,
) -> Result<ObservedImplementation, ImplementationObservationError> {
    let files = verified_files(input)?;
    let mut issues = Vec::new();
    let mut packages = parse_packages(&files)?;
    resolve_dependencies(&mut packages);
    let source_owners = source_owners(input.modules(), files.keys(), &mut issues);
    let (namespaces, source_contexts) =
        build_namespaces(&packages, &files, &source_owners, &mut issues)?;
    let package_by_manifest: BTreeMap<&str, &CargoPackage> = packages
        .iter()
        .map(|package| (package.manifest_path.as_str(), package))
        .collect();
    let package_by_name: BTreeMap<&str, &CargoPackage> = packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect();
    let mut observations = Vec::new();
    for (path, contexts) in source_contexts {
        let Some(owner) = source_owners.get(&path) else {
            continue;
        };
        let source = std::str::from_utf8(files[&path])
            .map_err(|_| ImplementationObservationError::NonUtf8Rust(path.clone().into()))?;
        let syntax = syn::parse_file(source).map_err(|source| {
            ImplementationObservationError::InvalidRustSource {
                path: path.clone().into(),
                source,
            }
        })?;
        let mut collector = ReferenceCollector::default();
        collector.visit_file(&syntax);
        issues.extend(collector.issues.into_iter().map(|detail| {
            ObservationIssue::new(ObservationIssueKind::Unsupported, path.clone(), detail)
        }));
        for context in contexts {
            let package = package_by_manifest[context.package_manifest.as_str()];
            let package_namespaces = &namespaces[context.package_manifest.as_str()];
            for reference in &collector.references {
                let resolved = resolve_reference(
                    reference,
                    &context,
                    package,
                    package_namespaces,
                    &package_by_name,
                    &source_owners,
                );
                observations.push(observation_from_resolution(
                    &path, owner, reference, resolved,
                ));
            }
        }
    }
    Ok(ObservedImplementation::compile(
        input.snapshot_fingerprint(),
        observations,
        issues,
    ))
}

fn verified_files(
    input: &ImplementationObservationInput,
) -> Result<BTreeMap<String, &[u8]>, ImplementationObservationError> {
    input
        .files()
        .iter()
        .map(|file| Ok((file.path().to_owned(), file.verified_bytes()?)))
        .collect()
}

fn parse_packages(
    files: &BTreeMap<String, &[u8]>,
) -> Result<Vec<CargoPackage>, ImplementationObservationError> {
    let mut packages = Vec::new();
    for (path, bytes) in files
        .iter()
        .filter(|(path, _)| path.ends_with("Cargo.toml"))
    {
        let source = std::str::from_utf8(bytes)
            .map_err(|_| ImplementationObservationError::NonUtf8Manifest(path.clone().into()))?;
        let document: CargoDocument = toml::from_str(source).map_err(|source| {
            ImplementationObservationError::InvalidCargoManifest {
                path: path.clone().into(),
                source,
            }
        })?;
        let Some(package) = document.package else {
            continue;
        };
        let manifest_dir = parent_path(path);
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
                let path = target.path.as_deref().unwrap_or("src/lib.rs");
                Some(join_path(&manifest_dir, path))
            },
        );
        let mut targets = Vec::new();
        if let Some(root) = &lib_root {
            targets.push(CargoTarget {
                root: root.clone(),
                kind: TargetKind::Library,
            });
        }
        targets.extend(document.bin.iter().filter_map(|target| {
            target.path.as_ref().map(|path| CargoTarget {
                root: join_path(&manifest_dir, path),
                kind: TargetKind::Other,
            })
        }));
        targets.extend(document.test.iter().filter_map(|target| {
            target.path.as_ref().map(|path| CargoTarget {
                root: join_path(&manifest_dir, path),
                kind: TargetKind::Other,
            })
        }));
        let default_main = join_path(&manifest_dir, "src/main.rs");
        if document.bin.is_empty() && files.contains_key(&default_main) {
            targets.push(CargoTarget {
                root: default_main,
                kind: TargetKind::Other,
            });
        }
        targets.sort_by(|left, right| left.root.cmp(&right.root));
        targets.dedup_by(|left, right| left.root == right.root);
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
        packages.push(CargoPackage {
            name: package.name,
            manifest_path: path.clone(),
            lib_name,
            lib_root,
            targets,
            dependencies,
        });
    }
    packages.sort_by(|left, right| left.manifest_path.cmp(&right.manifest_path));
    Ok(packages)
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

fn source_owners<'a>(
    modules: &'a [ModuleTerritory],
    paths: impl Iterator<Item = &'a String>,
    issues: &mut Vec<ObservationIssue>,
) -> BTreeMap<String, String> {
    let mut owners = BTreeMap::new();
    for path in paths.filter(|path| {
        std::path::Path::new(path.as_str())
            .extension()
            .is_some_and(|extension| extension == "rs")
    }) {
        let owner = modules
            .iter()
            .filter(|module| contains_path(module.path(), path))
            .max_by_key(|module| module.path().len());
        let Some(owner) = owner else {
            issues.push(ObservationIssue::new(
                ObservationIssueKind::Invalid,
                path,
                "governed Rust source has no physical Fortress Module owner",
            ));
            continue;
        };
        let relative = if owner.path().is_empty() {
            path.as_str()
        } else {
            path.strip_prefix(&format!("{}/", owner.path()))
                .unwrap_or(path)
        };
        if !relative.starts_with("code/") || relative["code/".len()..].contains('/') {
            issues.push(ObservationIssue::new(
                ObservationIssueKind::Invalid,
                path,
                format!(
                    "Rust source is not a direct Code element of its narrowest owner `{}`",
                    owner.id()
                ),
            ));
            continue;
        }
        owners.insert(path.clone(), owner.id().to_owned());
    }
    owners
}

type NamespaceBuild = (
    BTreeMap<String, PackageNamespaces>,
    BTreeMap<String, Vec<SourceContext>>,
);

fn build_namespaces(
    packages: &[CargoPackage],
    files: &BTreeMap<String, &[u8]>,
    owners: &BTreeMap<String, String>,
    issues: &mut Vec<ObservationIssue>,
) -> Result<NamespaceBuild, ImplementationObservationError> {
    let mut all_namespaces = BTreeMap::new();
    let mut contexts = BTreeMap::<String, Vec<SourceContext>>::new();
    for package in packages {
        let mut package_namespaces = PackageNamespaces::default();
        for target in &package.targets {
            if !files.contains_key(&target.root) {
                issues.push(ObservationIssue::new(
                    ObservationIssueKind::Invalid,
                    &target.root,
                    format!(
                        "Cargo target declared by `{}` does not exist in the snapshot",
                        package.manifest_path
                    ),
                ));
                continue;
            }
            let mut namespace = BTreeMap::new();
            discover_module_tree(
                &target.root,
                &[],
                files,
                owners,
                &mut namespace,
                &mut contexts,
                package,
                target,
                issues,
            )?;
            if target.kind == TargetKind::Library {
                package_namespaces.library.clone_from(&namespace);
            }
            package_namespaces
                .by_target
                .insert(target.root.clone(), namespace);
        }
        all_namespaces.insert(package.manifest_path.clone(), package_namespaces);
    }
    for values in contexts.values_mut() {
        values.sort_by(|left, right| {
            left.package_manifest
                .cmp(&right.package_manifest)
                .then_with(|| left.target_root.cmp(&right.target_root))
                .then_with(|| left.namespace.cmp(&right.namespace))
        });
        values.dedup_by(|left, right| {
            left.package_manifest == right.package_manifest
                && left.target_root == right.target_root
                && left.namespace == right.namespace
        });
    }
    Ok((all_namespaces, contexts))
}

#[allow(clippy::too_many_arguments)]
fn discover_module_tree(
    path: &str,
    namespace: &[String],
    files: &BTreeMap<String, &[u8]>,
    owners: &BTreeMap<String, String>,
    index: &mut BTreeMap<Vec<String>, NamespaceNode>,
    contexts: &mut BTreeMap<String, Vec<SourceContext>>,
    package: &CargoPackage,
    target: &CargoTarget,
    issues: &mut Vec<ObservationIssue>,
) -> Result<(), ImplementationObservationError> {
    let Some(owner) = owners.get(path) else {
        return Ok(());
    };
    index.insert(
        namespace.to_vec(),
        NamespaceNode {
            source_path: path.into(),
            owner: owner.clone(),
        },
    );
    contexts
        .entry(path.into())
        .or_default()
        .push(SourceContext {
            package_manifest: package.manifest_path.clone(),
            target_root: target.root.clone(),
            namespace: namespace.to_vec(),
        });
    let source = std::str::from_utf8(files[path])
        .map_err(|_| ImplementationObservationError::NonUtf8Rust(path.into()))?;
    let syntax = syn::parse_file(source).map_err(|source| {
        ImplementationObservationError::InvalidRustSource {
            path: path.into(),
            source,
        }
    })?;
    let mut queue = VecDeque::new();
    collect_modules(&syntax.items, path, namespace, &mut queue);
    while let Some(module) = queue.pop_front() {
        match module {
            DiscoveredModule::Inline { namespace, items } => {
                index.insert(
                    namespace.clone(),
                    NamespaceNode {
                        source_path: path.into(),
                        owner: owner.clone(),
                    },
                );
                collect_modules(&items, path, &namespace, &mut queue);
            }
            DiscoveredModule::External {
                namespace,
                declared_path,
                location,
            } => {
                if let Some(target_path) = resolve_module_file(path, &declared_path, files) {
                    discover_module_tree(
                        &target_path,
                        &namespace,
                        files,
                        owners,
                        index,
                        contexts,
                        package,
                        target,
                        issues,
                    )?;
                } else {
                    issues.push(ObservationIssue::new(
                        ObservationIssueKind::Invalid,
                        path,
                        format!(
                            "module declaration `{declared_path}` at {}:{} has no snapshot source",
                            location.line(),
                            location.column()
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

enum DiscoveredModule {
    Inline {
        namespace: Vec<String>,
        items: Vec<syn::Item>,
    },
    External {
        namespace: Vec<String>,
        declared_path: String,
        location: SourceLocation,
    },
}

fn collect_modules(
    items: &[syn::Item],
    source_path: &str,
    namespace: &[String],
    queue: &mut VecDeque<DiscoveredModule>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
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
            let declared_path = module_path_attribute(&module.attrs)
                .unwrap_or_else(|| default_module_path(source_path, &module.ident.to_string()));
            queue.push_back(DiscoveredModule::External {
                namespace: child,
                declared_path,
                location: source_location(module.ident.span()),
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
        let syn::Expr::Lit(literal) = &value.value else {
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
    let has_rust_extension = std::path::Path::new(declared_path)
        .extension()
        .is_some_and(|extension| extension == "rs");
    let direct = if declared_path.contains('/') || has_rust_extension {
        join_path(&parent_path(source_path), declared_path)
    } else {
        declared_path.into()
    };
    if files.contains_key(&direct) {
        return Some(direct);
    }
    let module_file = format!("{direct}.rs");
    if files.contains_key(&module_file) {
        return Some(module_file);
    }
    let module_root = format!("{direct}/mod.rs");
    files.contains_key(&module_root).then_some(module_root)
}

#[derive(Default)]
struct ReferenceCollector {
    references: Vec<CollectedReference>,
    aliases: BTreeMap<String, Vec<String>>,
    issues: Vec<String>,
}

impl<'ast> Visit<'ast> for ReferenceCollector {
    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        let conditionality = if has_cfg(&item.attrs) {
            Conditionality::Conditional
        } else {
            Conditionality::Unconditional
        };
        let mut expanded = Vec::new();
        expand_use_tree(Vec::new(), &item.tree, &mut expanded, &mut self.issues);
        for (path, alias, span) in expanded {
            if let Some(alias) = alias {
                self.aliases.insert(alias, path.clone());
            }
            self.references.push(CollectedReference {
                display: path.join("::"),
                path,
                span,
                conditionality,
            });
        }
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        self.references.push(CollectedReference {
            path: vec!["self".into(), item.ident.to_string()],
            display: format!("mod {}", item.ident),
            span: item.ident.span(),
            conditionality: if has_cfg(&item.attrs) {
                Conditionality::Conditional
            } else {
                Conditionality::Unconditional
            },
        });
        visit::visit_item_mod(self, item);
    }

    fn visit_path(&mut self, path: &'ast Path) {
        let segments: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let first = segments.first().map(String::as_str).unwrap_or_default();
        let imported = self.aliases.contains_key(first);
        let namespace_shaped = first
            .chars()
            .all(|character| character.is_ascii_lowercase() || character == '_');
        if segments.len() >= 2 && first != "Self" && (imported || namespace_shaped) {
            let mut expanded = segments.clone();
            if let Some(alias) = self.aliases.get(&segments[0]) {
                expanded = alias
                    .iter()
                    .cloned()
                    .chain(segments.iter().skip(1).cloned())
                    .collect();
            }
            self.references.push(CollectedReference {
                display: expanded.join("::"),
                path: expanded,
                span: path.span(),
                conditionality: Conditionality::Unconditional,
            });
        }
        visit::visit_path(self, path);
    }
}

fn expand_use_tree(
    prefix: Vec<String>,
    tree: &UseTree,
    output: &mut Vec<(Vec<String>, Option<String>, Span)>,
    issues: &mut Vec<String>,
) {
    match tree {
        UseTree::Path(path) => {
            let mut next = prefix;
            next.push(path.ident.to_string());
            expand_use_tree(next, &path.tree, output, issues);
        }
        UseTree::Name(name) => {
            let mut path = prefix;
            if name.ident != "self" {
                path.push(name.ident.to_string());
            }
            let alias = if name.ident == "self" {
                path.last().cloned()
            } else {
                Some(name.ident.to_string())
            };
            output.push((path, alias, name.ident.span()));
        }
        UseTree::Rename(rename) => {
            let mut path = prefix;
            path.push(rename.ident.to_string());
            output.push((path, Some(rename.rename.to_string()), rename.ident.span()));
        }
        UseTree::Group(group) => {
            for item in &group.items {
                expand_use_tree(prefix.clone(), item, output, issues);
            }
        }
        UseTree::Glob(glob) => {
            issues.push(format!(
                "glob import at {}:{} has unsupported symbol-level expansion",
                source_location(glob.star_token.span).line(),
                source_location(glob.star_token.span).column()
            ));
            output.push((prefix, None, glob.star_token.span));
        }
    }
}

enum ResolvedReference {
    Governed(String),
    External(String),
    Unresolved,
}

fn resolve_reference(
    reference: &CollectedReference,
    context: &SourceContext,
    package: &CargoPackage,
    namespaces: &PackageNamespaces,
    packages_by_name: &BTreeMap<&str, &CargoPackage>,
    owners: &BTreeMap<String, String>,
) -> ResolvedReference {
    let Some(first) = reference.path.first() else {
        return ResolvedReference::Unresolved;
    };
    if matches!(
        first.as_str(),
        "std"
            | "core"
            | "alloc"
            | "str"
            | "char"
            | "slice"
            | "mem"
            | "cmp"
            | "convert"
            | "iter"
            | "option"
            | "result"
    ) {
        return ResolvedReference::External(
            if matches!(first.as_str(), "std" | "core" | "alloc") {
                first.clone()
            } else {
                "core".into()
            },
        );
    }
    if first == "crate" || first == "self" || first == "super" {
        let namespace = relative_namespace(&reference.path, &context.namespace);
        return resolve_namespace(namespaces.by_target.get(&context.target_root), &namespace);
    }
    if first == &package.lib_name {
        return resolve_namespace(Some(&namespaces.library), &[]);
    }
    if let Some(dependency) = package.dependencies.get(first) {
        return match dependency {
            DependencyResolution::External(name) => ResolvedReference::External(name.clone()),
            DependencyResolution::WorkspacePackage(name) => {
                let Some(target_package) = packages_by_name.get(name.as_str()) else {
                    return ResolvedReference::Unresolved;
                };
                let Some(root) = target_package.lib_root.as_ref() else {
                    return ResolvedReference::Unresolved;
                };
                owners
                    .get(root)
                    .cloned()
                    .map_or(ResolvedReference::Unresolved, ResolvedReference::Governed)
            }
        };
    }
    let target_namespaces = namespaces.by_target.get(&context.target_root);
    if target_namespaces.is_some_and(|index| index.contains_key(&reference.path[..1])) {
        return resolve_namespace(target_namespaces, &reference.path);
    }
    let relative: Vec<String> = context
        .namespace
        .iter()
        .cloned()
        .chain(reference.path.iter().cloned())
        .collect();
    if target_namespaces.is_some_and(|index| {
        (1..=relative.len()).any(|length| index.contains_key(&relative[..length]))
    }) {
        return resolve_namespace(target_namespaces, &relative);
    }
    ResolvedReference::Unresolved
}

fn relative_namespace(path: &[String], current: &[String]) -> Vec<String> {
    match path.first().map(String::as_str) {
        Some("crate") => path[1..].to_vec(),
        Some("self") => current
            .iter()
            .cloned()
            .chain(path[1..].iter().cloned())
            .collect(),
        Some("super") => {
            let mut namespace = current.to_vec();
            let mut offset = 0;
            while path.get(offset).is_some_and(|segment| segment == "super") {
                namespace.pop();
                offset += 1;
            }
            namespace.extend(path[offset..].iter().cloned());
            namespace
        }
        _ => path.to_vec(),
    }
}

fn resolve_namespace(
    index: Option<&BTreeMap<Vec<String>, NamespaceNode>>,
    path: &[String],
) -> ResolvedReference {
    let Some(index) = index else {
        return ResolvedReference::Unresolved;
    };
    let shortest_candidate = usize::from(!path.is_empty());
    for length in (shortest_candidate..=path.len()).rev() {
        if let Some(node) = index.get(&path[..length]) {
            let _ = &node.source_path;
            return ResolvedReference::Governed(node.owner.clone());
        }
    }
    ResolvedReference::Unresolved
}

fn observation_from_resolution(
    source_path: &str,
    source_owner: &str,
    reference: &CollectedReference,
    resolved: ResolvedReference,
) -> ImplementationObservation {
    let (classification, target_module, external_target, status, resolved_target) = match resolved {
        ResolvedReference::Governed(target) => (
            TargetClassification::GovernedModule,
            Some(target.clone()),
            None,
            ResolutionStatus::Resolved,
            Some(target),
        ),
        ResolvedReference::External(target) => (
            TargetClassification::ExternalDependency,
            None,
            Some(target.clone()),
            ResolutionStatus::Resolved,
            Some(target),
        ),
        ResolvedReference::Unresolved => (
            TargetClassification::Unresolved,
            None,
            None,
            ResolutionStatus::Unresolved,
            None,
        ),
    };
    ImplementationObservation::new(
        source_owner,
        source_path,
        classification,
        target_module,
        external_target,
        reference.conditionality,
        ObservationProvenance::new(
            source_path,
            source_owner,
            &reference.display,
            source_location(reference.span),
            resolved_target,
        ),
        status,
    )
}

fn has_cfg(attributes: &[Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
}

fn source_location(span: Span) -> SourceLocation {
    let start = span.start();
    SourceLocation::new(
        u32::try_from(start.line).unwrap_or(u32::MAX),
        u32::try_from(start.column + 1).unwrap_or(u32::MAX),
    )
}

fn contains_path(module_path: &str, path: &str) -> bool {
    module_path.is_empty() || path == module_path || path.starts_with(&format!("{module_path}/"))
}

fn rust_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

fn parent_path(path: &str) -> String {
    path.rsplit_once('/')
        .map_or("", |(parent, _)| parent)
        .into()
}

fn join_path(base: &str, relative: &str) -> String {
    let mut parts: Vec<&str> = base.split('/').filter(|part| !part.is_empty()).collect();
    let normalized = relative.replace('\\', "/");
    for part in normalized.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            value => parts.push(value),
        }
    }
    parts.join("/")
}

const _: &str = RUST_LANGUAGE_ID;
