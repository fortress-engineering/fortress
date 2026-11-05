//! Native crate-root wiring for exact event path controls.

pub use fortress_core::behavioral_realization::RealizationCoverage;

#[path = "../../_code/event_graph.rs"]
mod event_graph;
mod event_graph_paths;
