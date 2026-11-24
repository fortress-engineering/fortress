//! Shared physical source capture for explicit native language observations.

use std::collections::BTreeSet;
use std::path::Path;

use crate::audit::{
    NativeObservationBinding, bind_native_observation_source, observe_candidate_source,
};
use crate::heavy_admission::{DirectoryIdentity, assert_no_incomplete_migration};
use crate::implementation_observation::{
    ImplementationObservationInput, SnapshotBoundFile, SourceOwnership, SourceOwnershipAuthority,
    SourceOwnershipBasis, SourceOwnershipDiagnostic,
};
use crate::observation::SourceView;

const MAX_DEPENDENCY_FILES: usize = 8192;
const MAX_DEPENDENCY_BYTES: usize = 32 << 20;

pub(crate) struct NativeSource<'a> {
    root: &'a Path,
    directory: DirectoryIdentity,
    pub(crate) view: SourceView,
    pub(crate) binding: NativeObservationBinding,
}

pub(crate) enum NativeSourceError {
    Unavailable(String),
    Changed,
}

impl<'a> NativeSource<'a> {
    pub(crate) fn capture(root: &'a Path, language: &str) -> Result<Self, NativeSourceError> {
        Self::capture_with(root, language, false)
    }

    pub(crate) fn capture_for_dependencies(
        root: &'a Path,
        language: &str,
    ) -> Result<Self, NativeSourceError> {
        Self::capture_with(root, language, true)
    }

    fn capture_with(
        root: &'a Path,
        language: &str,
        dependencies: bool,
    ) -> Result<Self, NativeSourceError> {
        let directory = DirectoryIdentity::capture(root).map_err(unavailable)?;
        let view = observe_source(root)?;
        let binding =
            bind_native_observation_source(&view, language, dependencies).map_err(unavailable)?;
        if !directory.matches(root).map_err(unavailable)? {
            return Err(NativeSourceError::Changed);
        }
        Ok(Self {
            root,
            directory,
            view,
            binding,
        })
    }

    pub(crate) fn dependency_input<'path>(
        &self,
        paths: impl IntoIterator<Item = &'path str>,
    ) -> Result<(ImplementationObservationInput, &[SourceOwnershipDiagnostic]), NativeSourceError>
    {
        let ownership = self
            .binding
            .dependency_ownership
            .as_ref()
            .ok_or_else(|| unavailable("Native dependency ownership was not selected"))?;
        let paths = paths.into_iter().collect::<BTreeSet<_>>();
        if paths.len() > MAX_DEPENDENCY_FILES {
            return Err(unavailable(
                "Native dependency input exceeds its file limit",
            ));
        }
        let mut size = 0usize;
        let mut files = Vec::with_capacity(paths.len());
        for &path in &paths {
            let bytes = self
                .view
                .bytes(path)
                .ok_or_else(|| unavailable("Native dependency source was not observed"))?;
            size = size.saturating_add(bytes.len());
            if size > MAX_DEPENDENCY_BYTES {
                return Err(unavailable(
                    "Native dependency input exceeds its byte limit",
                ));
            }
            files.push(SnapshotBoundFile::from_bytes(path, bytes));
        }
        let input = ImplementationObservationInput::new_with_ownership(
            &self.binding.source_fingerprint,
            files,
            ownership
                .ownerships()
                .iter()
                .filter(|owner| paths.contains(owner.source_path()))
                .cloned()
                .collect(),
        );
        Ok((input, ownership.diagnostics()))
    }

    pub(crate) fn original_declared_owner(
        &self,
        path: &str,
    ) -> Result<Option<SourceOwnership>, NativeSourceError> {
        let (input, diagnostics) = self.dependency_input([path])?;
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.source_path() == path)
        {
            return Ok(None);
        }
        let [owner] = input.ownerships() else {
            return Ok(None);
        };
        Ok(
            (owner.authority() == SourceOwnershipAuthority::DeclaredModule
                && owner.basis() == SourceOwnershipBasis::LogicalPathBinding)
                .then(|| owner.clone()),
        )
    }

    pub(crate) fn revalidate(&self) -> Result<(), NativeSourceError> {
        if observe_source(self.root)? != self.view
            || !self.directory.matches(self.root).map_err(unavailable)?
        {
            return Err(NativeSourceError::Changed);
        }
        Ok(())
    }
}

fn observe_source(root: &Path) -> Result<SourceView, NativeSourceError> {
    assert_no_incomplete_migration(root).map_err(unavailable)?;
    let view = observe_candidate_source(root).map_err(unavailable)?;
    assert_no_incomplete_migration(root).map_err(unavailable)?;
    Ok(view)
}

fn unavailable(error: impl std::fmt::Display) -> NativeSourceError {
    NativeSourceError::Unavailable(error.to_string())
}
