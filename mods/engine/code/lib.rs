//! Core standard and project-model foundations for Fortress.
//!
//! This crate owns provider-independent model logic. It must not depend on CLI
//! presentation, GitHub, a shell, an IDE, a CI provider, or a package ecosystem.

#![forbid(unsafe_code)]
#![deny(missing_docs, rustdoc::broken_intra_doc_links, warnings)]

#[path = "../mods/architecture_evaluation/code/architecture.rs"]
pub mod architecture;
#[path = "../mods/architecture_evaluation/code/diagnostics.rs"]
pub mod architecture_diagnostics;
#[path = "../mods/architecture_evaluation/code/realization.rs"]
pub mod architecture_realization;
#[path = "../mods/snapshot_governance/code/audit.rs"]
pub mod audit;
#[path = "../mods/behavioral_semantics/code/behavior.rs"]
pub mod behavioral_semantics;
#[path = "../mods/snapshot_governance/code/contract.rs"]
pub mod contract;
#[path = "../mods/contract_coherency/code/contract.rs"]
pub mod contract_coherency;
#[path = "../mods/snapshot_governance/code/documentation.rs"]
pub mod documentation;
#[path = "../mods/snapshot_governance/code/evaluation.rs"]
pub mod evaluation;
#[path = "../mods/finding_model/code/finding.rs"]
pub mod finding;
#[path = "../mods/standard_registry/code/identity.rs"]
pub mod identity;
#[path = "../mods/implementation_observation/code/observation.rs"]
pub mod implementation_observation;
#[path = "../mods/repository_observation/code/observation.rs"]
pub mod observation;
#[path = "../mods/snapshot_governance/code/ownership.rs"]
pub mod ownership;
#[path = "../mods/snapshot_governance/code/placement.rs"]
pub mod placement;
#[path = "../mods/program_semantics/code/program.rs"]
pub mod program_semantics;
#[path = "../mods/project_model/code/project.rs"]
pub mod project;
#[path = "../mods/snapshot_governance/code/rust_test_analyzer.rs"]
pub mod rust_test_analyzer;
#[path = "../mods/semantic_analysis/code/semantic.rs"]
pub mod semantic_analysis;
#[path = "../mods/snapshot_governance/code/snapshot.rs"]
pub mod snapshot;
#[path = "../mods/standard_registry/code/standard.rs"]
pub mod standard;
#[path = "../mods/snapshot_governance/code/testing_boundary.rs"]
pub mod testing_boundary;
#[path = "../mods/snapshot_governance/code/traceability.rs"]
pub mod traceability;
