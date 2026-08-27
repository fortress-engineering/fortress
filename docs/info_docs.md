# Info

## Role

Persist computational output whose exact content is required for reproducible repository operation.

## Production

Cargo produces the resolver lock record from package constraints. The Contract Coherency compiler produces the self-CCG from canonical contracts, recursive containment, standard logic, and supported verification facts.

## Semantics

The lock record identifies one exact dependency resolution. The CCG records the deterministic derived semantic ecosystem, its provenance, effective obligations, relationships, support topology, and supported coherency result without becoming authored intent authority or certification evidence.

## Lifecycle

Cargo regenerates the lock record when dependency inputs change. Fortress regenerates the CCG whenever one of its explicit semantic inputs changes, and CI rejects a stale committed projection. Build products remain transient outside the repository.

## Files

### [`Cargo.lock`](../info/Cargo.lock)

Records Cargo-produced exact dependency resolution for reproducible builds under the configured external lockfile path.

### [`contract_coherency_graph.json`](../info/contract_coherency_graph.json)

Persists Fortress's canonical derived self-CCG so local and hosted gates can compare fresh compiler output byte for byte.
