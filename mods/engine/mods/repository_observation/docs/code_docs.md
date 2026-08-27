# Repository Observation Code

`observation.rs` walks the repository without Git-provider assumptions,
normalizes explicit exclusions, hashes ordinary-file bytes, and emits a sorted
inventory. Host filesystem reads and SHA-256 remain inside the local trust
boundary.
