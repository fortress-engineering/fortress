//! Core standard and project-model foundations for Fortress.
//!
//! This crate owns provider-independent model logic. It must not depend on CLI
//! presentation, GitHub, a shell, an IDE, a CI provider, or a package ecosystem.

#![forbid(unsafe_code)]
#![deny(missing_docs, rustdoc::broken_intra_doc_links, warnings)]

pub mod architecture;
pub mod command;
pub mod evaluation;
pub mod feature;
pub mod finding;
pub mod identity;
pub mod observation;
pub mod ownership;
pub mod project;
pub mod rust_test_analyzer;
pub mod snapshot;
pub mod standard;
pub mod traceability;
