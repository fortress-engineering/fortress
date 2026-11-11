//! Checked regular-file paths and non-overwriting publication primitives.
use std::fs;
use std::path::{Path, PathBuf};

use super::journal::{io_error, linked, read_regular};
use super::{
    MAX_MIGRATION_BYTES, MigrationError, MigrationResourceLease, content_digest, fail,
    validate_path,
};

pub(crate) fn checked_path(root: &Path, relative: &str) -> Result<PathBuf, MigrationError> {
    validate_path(relative)?;
    checked_relative(root, relative)
}
pub(crate) fn checked_relative(root: &Path, relative: &str) -> Result<PathBuf, MigrationError> {
    if !crate::observation::is_canonical_relative_path(relative)
        || relative.split('/').any(|p| p.eq_ignore_ascii_case(".git"))
    {
        return Err(fail("UNSAFE_PATH", relative));
    }
    let root_metadata = fs::symlink_metadata(root).map_err(io_error)?;
    if linked(&root_metadata) || !root_metadata.is_dir() {
        return Err(fail("UNSAFE_REPOSITORY", root.display().to_string()));
    }
    let components = relative.split('/').collect::<Vec<_>>();
    let mut path = root.to_path_buf();
    let mut missing = false;
    for (i, name) in components.iter().enumerate() {
        let parent = path.clone();
        path.push(name);
        if missing {
            continue;
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if linked(&metadata) || (i + 1 < components.len() && !metadata.is_dir()) {
                    return Err(fail("UNSAFE_PATH_KIND", relative));
                }
                let exact = fs::read_dir(parent).map_err(io_error)?.any(|entry| {
                    entry
                        .ok()
                        .is_some_and(|e| e.file_name().to_str() == Some(*name))
                });
                if !exact {
                    return Err(fail("CASE_MISMATCH", relative));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => missing = true,
            Err(error) => return Err(io_error(error)),
        }
    }
    Ok(path)
}
pub(crate) fn observed_file(path: &Path) -> Result<Option<Vec<u8>>, MigrationError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(error)),
        Ok(_) => read_regular(path, MAX_MIGRATION_BYTES).map(Some),
    }
}
pub(crate) fn require_absent(path: &Path) -> Result<(), MigrationError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
        Ok(_) => Err(fail(
            "PATH_CONFLICT",
            format!("destination already exists: {}", path.display()),
        )),
    }
}
pub(crate) fn require_owned_file(
    lease: &impl MigrationResourceLease,
    path: &Path,
    expected_id: &str,
    digest: &str,
) -> Result<(), MigrationError> {
    let bytes = read_regular(path, MAX_MIGRATION_BYTES)?;
    if content_digest(&bytes) != digest || lease.object_identity(path)? != expected_id {
        return Err(fail(
            "OWNERSHIP_CONFLICT",
            format!(
                "object is not the exclusively owned known image: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}
pub(crate) fn sync_directory(path: &Path) -> Result<(), MigrationError> {
    #[cfg(unix)]
    {
        fs::File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(io_error)
    }
    #[cfg(not(unix))]
    {
        // Journal and content files are synchronized individually. Portable Rust does
        // not establish power-loss ordering for Windows directory metadata. Receipts
        // and documentation therefore qualify process-crash recovery, not power loss.
        let metadata = fs::symlink_metadata(path).map_err(io_error)?;
        if linked(&metadata) || !metadata.is_dir() {
            return Err(fail("UNSAFE_PATH_KIND", path.display().to_string()));
        }
        Ok(())
    }
}
