//! Native crate-root wiring for the parent-local field aggregation controls.

pub use fortress_core::program_semantics;

#[path = "field_projection.rs"]
mod controls;
#[path = "../../_code/field_projection.rs"]
mod field_projection;
