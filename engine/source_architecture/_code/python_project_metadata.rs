//! Static declarations from a bounded, exact pyproject.toml.

use std::collections::BTreeSet;

use serde::Serialize;
use toml::{Table, Value};

const MAX_METADATA_BYTES: usize = 128 << 10;
const MAX_DECLARATION_BYTES: usize = 2048;
const MAX_DYNAMIC_FIELDS: usize = 64;

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum PythonProjectMetadata {
    Missing,
    Unavailable {
        reason: &'static str,
    },
    Invalid {
        reason: &'static str,
    },
    Declared {
        project: Option<PythonProjectFields>,
        build_system: Option<PythonBuildFields>,
    },
}

#[derive(Serialize)]
pub(crate) struct PythonProjectFields {
    name: String,
    version: Option<String>,
    requires_python: Option<String>,
    dynamic: BTreeSet<String>,
}

#[derive(Serialize)]
pub(crate) struct PythonBuildFields {
    backend: Option<String>,
    backend_path_declared: bool,
}

pub(crate) fn inspect_pyproject(bytes: Option<&[u8]>) -> PythonProjectMetadata {
    let Some(bytes) = bytes else {
        return PythonProjectMetadata::Missing;
    };
    if bytes.len() > MAX_METADATA_BYTES {
        return PythonProjectMetadata::Unavailable {
            reason: "RESOURCE_LIMIT",
        };
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return PythonProjectMetadata::Invalid {
            reason: "INVALID_UTF8",
        };
    };
    let Ok(document) = toml::from_str::<Table>(text) else {
        return PythonProjectMetadata::Invalid {
            reason: "INVALID_TOML",
        };
    };
    let Ok(project) = selected_table(&document, "project")
        .and_then(|table| table.map(inspect_project).transpose())
    else {
        return PythonProjectMetadata::Invalid {
            reason: "INVALID_SELECTED_PROJECT_DECLARATIONS",
        };
    };
    let Ok(build_system) = selected_table(&document, "build-system")
        .and_then(|table| table.map(inspect_build_system).transpose())
    else {
        return PythonProjectMetadata::Invalid {
            reason: "INVALID_SELECTED_BUILD_DECLARATIONS",
        };
    };
    PythonProjectMetadata::Declared {
        project,
        build_system,
    }
}

fn selected_table<'a>(document: &'a Table, name: &str) -> Result<Option<&'a Table>, ()> {
    document
        .get(name)
        .map(|value| value.as_table().ok_or(()))
        .transpose()
}

fn inspect_project(project: &Table) -> Result<PythonProjectFields, ()> {
    let name = selected_string(project, "name")?.ok_or(())?;
    let version = selected_string(project, "version")?;
    let requires_python = selected_string(project, "requires-python")?;
    let mut dynamic = BTreeSet::new();
    if let Some(value) = project.get("dynamic") {
        let fields = value.as_array().ok_or(())?;
        if fields.len() > MAX_DYNAMIC_FIELDS {
            return Err(());
        }
        for field in fields {
            let field = bounded_string(field)?;
            if field == "name" || project.contains_key(field) || !dynamic.insert(field.to_owned()) {
                return Err(());
            }
        }
    }
    if version.is_none() && !dynamic.contains("version") {
        return Err(());
    }
    Ok(PythonProjectFields {
        name,
        version,
        requires_python,
        dynamic,
    })
}

fn inspect_build_system(build: &Table) -> Result<PythonBuildFields, ()> {
    let requires = build.get("requires").and_then(Value::as_array).ok_or(())?;
    if !requires.iter().all(Value::is_str) {
        return Err(());
    }
    let backend = selected_string(build, "build-backend")?;
    let backend_path_declared = build
        .get("backend-path")
        .map(|value| {
            value
                .as_array()
                .filter(|paths| paths.iter().all(Value::is_str))
                .ok_or(())
        })
        .transpose()?
        .is_some();
    Ok(PythonBuildFields {
        backend,
        backend_path_declared,
    })
}

fn selected_string(table: &Table, field: &str) -> Result<Option<String>, ()> {
    table
        .get(field)
        .map(|value| bounded_string(value).map(str::to_owned))
        .transpose()
}

fn bounded_string(value: &Value) -> Result<&str, ()> {
    value
        .as_str()
        .filter(|text| {
            !text.is_empty()
                && text.len() <= MAX_DECLARATION_BYTES
                && !text.chars().any(char::is_control)
        })
        .ok_or(())
}
