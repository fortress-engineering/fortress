//! Authoritative physical Module indexing for canonical Project Filing.
//!
//! Module ancestry is derived exactly once from direct, contract-marked child
//! directories. Consumers may attach semantic contract identities and logical
//! bindings, but must not rediscover canonical ancestry independently.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Canonical semantic Element names and their physical directory mappings.
pub const ELEMENT_MAPPINGS: [(&str, &str); 4] = [
    ("code", "_code"),
    ("data", "_data"),
    ("docs", "_docs"),
    ("info", "_info"),
];

/// The exact Fortress-reserved structural directory names.
pub const RESERVED_STRUCTURAL_DIRECTORIES: [&str; 4] = ["_code", "_data", "_docs", "_info"];

/// One indexed canonical physical Module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalModuleEntry {
    path: String,
    parent: Option<String>,
    children: Vec<String>,
    elements: BTreeMap<String, String>,
}

impl CanonicalModuleEntry {
    /// Returns the repository-relative Module root; the project root is empty.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the canonical physical parent Module root.
    #[must_use]
    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    /// Returns directly nested child Module roots in canonical order.
    #[must_use]
    pub fn children(&self) -> &[String] {
        &self.children
    }

    /// Returns semantic Element name to physical path mappings.
    #[must_use]
    pub const fn elements(&self) -> &BTreeMap<String, String> {
        &self.elements
    }

    /// Returns the physical root for one semantic Element.
    #[must_use]
    pub fn element_path(&self, semantic_name: &str) -> Option<&str> {
        self.elements.get(semantic_name).map(String::as_str)
    }
}

/// The single deterministic canonical physical Module index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalModuleIndex {
    entries: BTreeMap<String, CanonicalModuleEntry>,
}

impl CanonicalModuleIndex {
    /// Indexes direct, contract-marked Modules from repository-relative files.
    ///
    /// `ecosystem_directory` is queried only for direct Module-root directory
    /// entries. A matching entry is opaque and is never traversed for Module
    /// contracts.
    #[must_use]
    pub fn from_paths<'a, I, F>(paths: I, ecosystem_directory: F) -> Self
    where
        I: IntoIterator<Item = &'a str>,
        F: Fn(&str, &str) -> bool,
    {
        let files = paths.into_iter().collect::<BTreeSet<_>>();
        let directories = observed_directories(&files);
        let mut parents = BTreeMap::<String, Option<String>>::from([(String::new(), None)]);
        let mut queue = VecDeque::from([String::new()]);

        while let Some(module) = queue.pop_front() {
            for directory in directories
                .iter()
                .filter(|directory| parent_path(directory) == Some(module.as_str()))
            {
                let name = file_name(directory);
                if RESERVED_STRUCTURAL_DIRECTORIES.contains(&name)
                    || name.starts_with('_')
                    || ecosystem_directory(&module, name)
                {
                    continue;
                }
                let marker = child_path(directory, "contract.json");
                if files.contains(marker.as_str()) && !parents.contains_key(directory) {
                    parents.insert(directory.clone(), Some(module.clone()));
                    queue.push_back(directory.clone());
                }
            }
        }

        let paths = parents.keys().cloned().collect::<Vec<_>>();
        let mut entries = BTreeMap::new();
        for path in &paths {
            let children = parents
                .iter()
                .filter_map(|(candidate, parent)| {
                    (parent.as_deref() == Some(path.as_str())).then_some(candidate.clone())
                })
                .collect();
            let elements = ELEMENT_MAPPINGS
                .into_iter()
                .filter_map(|(semantic, physical)| {
                    let element = child_path(path, physical);
                    directories
                        .contains(&element)
                        .then_some((semantic.to_owned(), element))
                })
                .collect();
            entries.insert(
                path.clone(),
                CanonicalModuleEntry {
                    path: path.clone(),
                    parent: parents.get(path).cloned().flatten(),
                    children,
                    elements,
                },
            );
        }
        Self { entries }
    }

    /// Returns every indexed Module keyed by physical root.
    #[must_use]
    pub const fn entries(&self) -> &BTreeMap<String, CanonicalModuleEntry> {
        &self.entries
    }

    /// Returns one indexed Module by physical root.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&CanonicalModuleEntry> {
        self.entries.get(path)
    }

    /// Returns all canonical Module roots in deterministic order.
    #[must_use]
    pub fn paths(&self) -> BTreeSet<String> {
        self.entries.keys().cloned().collect()
    }

    /// Returns the deepest indexed Module containing a repository path.
    #[must_use]
    pub fn owning_module<'a>(&'a self, path: &str) -> &'a str {
        let mut cursor = parent_path(path);
        while let Some(candidate) = cursor {
            if let Some((indexed, _)) = self.entries.get_key_value(candidate) {
                return indexed;
            }
            cursor = parent_path(candidate);
        }
        ""
    }
}

/// Returns whether a child Module name is canonical lowercase snake case.
#[must_use]
pub fn is_module_name(name: &str) -> bool {
    let mut components = name.split('_');
    let Some(first) = components.next() else {
        return false;
    };
    let alphanumeric = |component: &str| {
        !component.is_empty()
            && component
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    };
    !first.is_empty()
        && first.as_bytes()[0].is_ascii_lowercase()
        && alphanumeric(first)
        && components.all(alphanumeric)
}

fn observed_directories(files: &BTreeSet<&str>) -> BTreeSet<String> {
    let mut directories = BTreeSet::new();
    for path in files {
        let segments = path.split('/').collect::<Vec<_>>();
        for end in 1..segments.len() {
            directories.insert(segments[..end].join("/"));
        }
    }
    directories
}

fn parent_path(path: &str) -> Option<&str> {
    path.rsplit_once('/').map_or_else(
        || (!path.is_empty()).then_some(""),
        |(parent, _)| Some(parent),
    )
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn child_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_owned()
    } else {
        format!("{parent}/{child}")
    }
}
