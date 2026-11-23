//! Shared physical source capture for explicit native language observations.

use std::path::Path;

use crate::audit::{
    NativeObservationBinding, bind_native_observation_source, observe_candidate_source,
};
use crate::heavy_admission::{DirectoryIdentity, assert_no_incomplete_migration};
use crate::observation::SourceView;

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
        let directory = DirectoryIdentity::capture(root).map_err(unavailable)?;
        let view = observe_source(root)?;
        let binding = bind_native_observation_source(&view, language).map_err(unavailable)?;
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
