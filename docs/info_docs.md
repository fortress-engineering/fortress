# Info

## Role

Persist computational output whose exact content is required for reproducible repository operation.

## Production

Cargo produces the resolver lock record from package constraints. The Contract Coherency compiler produces the self-CCG from canonical contracts, recursive containment, standard logic, and supported verification facts. Behavioral Semantics produces the self-BFG from CCG-preserved authored checkpoints and graph semantics. Program Semantics produces the self-PSM from the exact semantic source identity, snapshot-bound Cargo manifests, recursive Module ownership, and structurally parsed Rust source. Semantic Analysis produces its result from the PSM and distributed authored Function Contracts. State and Effect Analysis produces its result from the PSM, Semantic Analysis, distributed State Contracts, and Function Contract v3 state/effect obligations. Information Flow Analysis produces its result from those semantic layers, project-defined ordered facets, and Function Contract v3 flow declarations.

## Semantics

The lock record identifies one exact dependency resolution. The CCG records the deterministic derived semantic ecosystem, its provenance, effective obligations, relationships, support topology, and supported coherency result. The Intended BFG records meaningful Feature-flow intent, Module lanes, boundary crossings, branches, loops, dominators, post-dominators, provenance, and explicit unsupported semantics. The PSM records observed nominal Rust declarations and impls, executable symbols, typed interfaces and supported local expressions, type-directed and residual calls, structured places and mutations, bounded value transfers, call topology, coverage states, and analyzer coherency. Semantic Analysis records conservative value domains, fixed-point summaries, contract proof checks, abstract counter-domains, and property-specific uncertainty. State and Effect Analysis records conservative typestate classifications and transitions, direct and transitive effect closure, contract checks, causal evidence, and explicit uncertainty. Information Flow Analysis records project-facet classifications, explicit propagation and field-flow summaries, sink checks, abstract counter-labels, trusted-transition diagnostics, and property-specific uncertainty without becoming authored authority, comprehensive security proof, or certification evidence.

## Lifecycle

Cargo regenerates the lock record when dependency inputs change. Fortress regenerates the CCG whenever one of its explicit semantic inputs changes, the BFG whenever its CCG or authored behavior changes, the PSM whenever its explicit semantic source identity or analyzer changes, Semantic Analysis whenever the PSM, Function Contracts, or analyzer semantics change, State and Effect Analysis whenever the PSM, Semantic Analysis, State Contracts, Function Contracts, or analyzer semantics change, and Information Flow Analysis whenever any semantic substrate, policy, Function Contract, or analyzer semantics change; CI rejects any stale committed projection. Build products remain transient outside the repository.

## Files

### [`Cargo.lock`](../info/Cargo.lock)

Records Cargo-produced exact dependency resolution for reproducible builds under the configured external lockfile path.

### [`behavioral_flow_graph.json`](../info/behavioral_flow_graph.json)

Persists Fortress's canonical derived Intended BFG v1 so local and hosted gates can compare fresh behavioral compilation byte for byte without claiming implementation realization.

### [`contract_coherency_graph.json`](../info/contract_coherency_graph.json)

Persists Fortress's canonical derived self-CCG so local and hosted gates can compare fresh compiler output byte for byte.

### [`information_flow_analysis.json`](../info/information_flow_analysis.json)

Persists Fortress's canonical derived Information Flow Analysis v1 so local and hosted gates can compare source/sink classifications, explicit propagation, trusted transitions, counter-labels, and uncertainty byte for byte without implying comprehensive security proof.

### [`program_semantic_model.json`](../info/program_semantic_model.json)

Persists Fortress's canonical derived self-PSM v3 so local and hosted gates can compare nominal, type-directed, structured mutation, snapshot-bound executable semantics byte for byte without claiming full heap flow, state correctness, capability realization, or behavioral realization.

### [`semantic_analysis.json`](../info/semantic_analysis.json)

Persists Fortress's canonical derived Semantic Analysis v1 so local and hosted gates can compare supported function-domain consequences byte for byte while retaining partial, unknown, and unsupported properties explicitly.

### [`state_effect_analysis.json`](../info/state_effect_analysis.json)

Persists Fortress's canonical derived State and Effect Analysis v1 so local and hosted gates can compare typestate transitions, transitive effects, contract checks, causal evidence, and uncertainty byte for byte.
