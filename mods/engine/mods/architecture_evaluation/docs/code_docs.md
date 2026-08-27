# Architecture Evaluation Code

`architecture.rs` loads typed zones, components, owned paths, artifacts, and
dependencies, rejects duplicates and unknown targets, and emits the shared
canonical finding for `ARCH-DEPENDENCY-001` cycles.
