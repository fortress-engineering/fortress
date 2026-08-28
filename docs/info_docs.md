# Info

## Role

Persist computational output whose exact content is required for reproducible repository operation.

## Production

Cargo produces the resolver lock record from package constraints. The Contract Coherency compiler produces the self-CCG from canonical contracts, recursive containment, standard logic, and supported verification facts. Behavioral Semantics produces the self-BFG from CCG-preserved authored checkpoints and graph semantics. Program Semantics produces the self-PSM from the exact semantic source identity, snapshot-bound Cargo manifests, recursive Module ownership, and structurally parsed Rust source. Semantic Analysis produces its result from the PSM and distributed authored Function Contracts. State and Effect Analysis produces its result from the PSM, Semantic Analysis, distributed State Contracts, and Function Contract v3 state/effect obligations. Information Flow Analysis produces its result from those semantic layers, project-defined ordered facets, and Function Contract v3 flow declarations. Environmental Semantics produces its result from the complete semantic substrate and distributed Module-local Environment Contracts. Behavioral Realization produces the self-Realized BFG from the Intended BFG, the complete implementation-semantic stack, and distributed Behavior Realization Contracts. Certification produces the Evidence Graph, exact-profile Certification result, and Verified BFG from current semantic artifacts, applicable rule results, local unfiltered Rust execution, and Testing-owned verification bindings. The local quality-certificate issuer executes the complete canonical gate profile and records its deterministic content and artifact fingerprints for lightweight hosted freshness verification.

## Semantics

The lock record identifies one exact dependency resolution. The CCG records the deterministic derived semantic ecosystem, its provenance, effective obligations, relationships, support topology, and supported coherency result. The Intended BFG records meaningful Feature-flow intent, Module lanes, boundary crossings, branches, loops, dominators, post-dominators, provenance, and explicit unsupported semantics. The PSM records observed nominal Rust declarations and impls, executable symbols, typed interfaces and supported local expressions, type-directed and residual calls, structured places and mutations, bounded value transfers, call topology, coverage states, and analyzer coherency. Semantic Analysis records conservative value domains, fixed-point summaries, contract proof checks, abstract counter-domains, and property-specific uncertainty. State and Effect Analysis records conservative typestate classifications and transitions, direct and transitive effect closure, contract checks, causal evidence, and explicit uncertainty. Information Flow Analysis records project-facet classifications, explicit propagation and field-flow summaries, sink checks, abstract counter-labels, trusted-transition diagnostics, and property-specific uncertainty. Environmental Analysis records admissible nondeterministic outcomes, handling status, completion certainty, qualitative timing, retry/idempotency, duplicate delivery, bounded interruption/recovery, deterministic fault scenarios, and property-specific uncertainty. The Realized BFG records exact semantic checkpoint anchors, coverage-aware implementation events, next meaningful checkpoint transitions, intended/realized edge states, proven dominator bypasses, terminal and decision reconciliation, derivation evidence, and unestablished verification obligations. The Evidence Graph records immutable authority, observation, proof, execution, scenario, assertion, and aggregate nodes with dependency-addressed identities. Certification evaluates those nodes using `INVALID > FAIL > STALE > MISSING > PASS`. The Verified BFG preserves intended, realized, and executed/static verification dimensions separately. The local quality certificate binds PASS results to every governed repository byte except its own canonical file and to all eleven derived artifact digests; its SHA-256 stamp is tamper-evident and stale-resistant but explicitly not an authenticated signature or release attestation.

## Lifecycle

Cargo regenerates the lock record when dependency inputs change. Fortress regenerates each semantic artifact whenever its explicit upstream identities change, the Evidence Graph whenever an authority, observation, proof, execution, binding, or assertion identity changes, Certification whenever its exact subject/profile obligations change, and the Verified BFG whenever intended, realized, or evidence inputs change. Historical evidence remains cryptographically valid about its old subject but is stale for a different subject. Maintainers issue certification and the quality certificate only after the complete local gate profile succeeds; hosted CI recomputes repository/artifact fingerprints, PASS claims, and digest stamps without rerunning the long semantic suite. Build products remain transient outside the repository.

## Files

### [`Cargo.lock`](../info/Cargo.lock)

Records Cargo-produced exact dependency resolution for reproducible builds under the configured external lockfile path.

### [`behavioral_flow_graph.json`](../info/behavioral_flow_graph.json)

Persists Fortress's canonical derived Intended BFG v1 so local and hosted gates can compare fresh behavioral compilation byte for byte without claiming implementation realization.

### [`contract_coherency_graph.json`](../info/contract_coherency_graph.json)

Persists Fortress's canonical derived self-CCG so local and hosted gates can compare fresh compiler output byte for byte.

### [`environmental_analysis.json`](../info/environmental_analysis.json)

Persists Fortress's canonical derived Environmental Analysis v1 so local and hosted gates can compare outcome handling, retry/idempotency, bounded recovery, fault scenarios, and uncertainty byte for byte without implying comprehensive fault-tolerance proof.

### [`evidence_graph.json`](../info/evidence_graph.json)

Persists the content-addressed Evidence Graph v1 for the exact certification source, including obligation dependencies and current local execution/scenario evidence without embedding copies of semantic artifacts.

### [`certification.json`](../info/certification.json)

Persists the exact `CERT-FULL-SNAPSHOT-V1` result, certification root digest, obligation statuses, trusted-assertion dependencies, and deterministic status summary.

### [`information_flow_analysis.json`](../info/information_flow_analysis.json)

Persists Fortress's canonical derived Information Flow Analysis v1 so local and hosted gates can compare source/sink classifications, explicit propagation, trusted transitions, counter-labels, and uncertainty byte for byte without implying comprehensive security proof.

### [`program_semantic_model.json`](../info/program_semantic_model.json)

Persists Fortress's canonical derived self-PSM v3 so local and hosted gates can compare nominal, type-directed, structured mutation, snapshot-bound executable semantics byte for byte without claiming full heap flow, state correctness, capability realization, or behavioral realization.

### [`quality_certificate.json`](../info/quality_certificate.json)

Records the deterministic local-development quality-gate PASS claim, complete repository input fingerprint, canonical gate commands, every derived artifact digest, deterministic audit digest, and a tamper-evident certificate stamp. Its authenticity is explicitly UNVERIFIED because no external trusted signing identity is configured.

### [`realized_behavioral_flow_graph.json`](../info/realized_behavioral_flow_graph.json)

Persists Fortress's canonical derived Realized BFG v1 so local and hosted gates can compare exact checkpoint realization, meaningful edge reconciliation, dominator-bypass conclusions, coverage, and unestablished verification obligations byte for byte without claiming runtime trace evidence or a Verified BFG.

### [`semantic_analysis.json`](../info/semantic_analysis.json)

Persists Fortress's canonical derived Semantic Analysis v1 so local and hosted gates can compare supported function-domain consequences byte for byte while retaining partial, unknown, and unsupported properties explicitly.

### [`state_effect_analysis.json`](../info/state_effect_analysis.json)

Persists Fortress's canonical derived State and Effect Analysis v1 so local and hosted gates can compare typestate transitions, transitive effects, contract checks, causal evidence, and uncertainty byte for byte.

### [`verified_behavioral_flow_graph.json`](../info/verified_behavioral_flow_graph.json)

Persists Verified BFG v1 as the evidence-aware projection of Intended and Realized BFG facts, preserving static and executed verification specificity without attributing Feature tests to exact edges absent explicit bindings.
