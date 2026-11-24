# Data

## Role

Persist authored inputs and machine contracts directly consumed by this Module.

## Origin

Maintainers author these files under project, schema, standard, Cargo, or capability authority according to each element description.

## Semantics

The Data declares configuration, structure, identity, applicability, or normative input meaning used by the Module; it is not computational output.

## Validity

Consumers require valid UTF-8 where textual, correct schema or ecosystem syntax, canonical identities and paths, complete required fields, and compatible declared versions.

## Lifecycle

Maintainers update Data through reviewed semantic changes; schema versions change only when representation identity changes, while Git retains superseded history.

## Files

### [`collector_registration_schema_v1.json`](../_data/collector_registration_schema_v1.json)

Defines the local host registration, including absolute tool and script selectors and exact digests.

### [`collector_report_schema_v1.json`](../_data/collector_report_schema_v1.json)

Defines the typed collector projection, original bytes, normalized envelope and explicit assurance limitations.

### [`extension_guide.txt`](../_data/extension_guide.txt)

Describes exact local extension selection, independently executable SDK tests, and the boundary between importer output and trusted evidence admission.

### [`Cargo.toml`](../_data/Cargo.toml)

Declares the fortress-cli package and explicit library, binary, and process-level verification targets.

### [`command_schema_v1.json`](../_data/command_schema_v1.json)

Defines the version-one machine contract for command declarations.

### [`commands.json`](../_data/commands.json)

Declares the exact implemented command instances exposed by the native registry. The flow-author entry records explicit source preparation and unapplied policy proposals; it grants no authority or certification.

### [`offline_verifier_v1.txt`](../_data/offline_verifier_v1.txt)

Embeds the exact standalone public Python consumer from Testing as an immutable CLI resource. Regenerate this byte-for-byte copy from `testing/_code/verify_bundle.py` when that consumer changes. The CLI regression gate rejects drift; the adapter executes these reviewed bytes in isolated Python, never a candidate repository script. This resource introduces no second implementation or authority.

### [`install_guide.txt`](../_data/install_guide.txt)

Provides the reviewed Markdown installation guide bundled with the local development archive. It explains the platform prerequisites, verification steps, editor and MCP setup, and exact application-slot lifecycle.

### [`package_manifest_schema_v1.json`](../_data/package_manifest_schema_v1.json)

Describes the local development package inventory, native target, exact source binding, compatibility fields, and explicit authenticity and release-authorization states.

### [`go_collector_schema_v1.json`](../_data/go_collector_schema_v1.json)

Defines the explicit host-owned Go compiler registration, including the exact
executable and toolchain. Runtime admission requires an ordinary absolute host
asset outside the selected repository.

### [go_collector_schema_v2.json](../_data/go_collector_schema_v2.json)

Defines the explicit external host registration for the native Go build-selection mode. The trusted host pins the combined helper and declares its exact bounded compiler and test context.

### [python_worker_schema_v1.json](../_data/python_worker_schema_v1.json)

Versioned host registration for the independently selected interpreter. The schema requires an absolute host interpreter and worker path in production. The executable SHA-256, runtime descriptor hash and exact grammar identify the selected binding. The worker path must contain the reviewed implementation shipped with the running Fortress executable.

### [python_lexical_schema_v1.json](../_data/python_lexical_schema_v1.json)

Versioned Python lexical observation envelope. It records the exact source, context, authority, selected interpreter, registration and resource profile. The nested Source Architecture report retains syntax, scope, module validity, source spans and explicit runtime limitations. This shape is an observational projection, with no portable authority or assessment meaning.

### [go_collector_schema_v3.json](../_data/go_collector_schema_v3.json)

Defines the external host registration for the bounded native Go module observer. The host supplies a reviewed executable digest, the exact runtime edition, and the selected build context independently of repository bytes.

### [python_scalar_worker_schema_v1.json](../_data/python_scalar_worker_schema_v1.json)

Versioned external registration for explicit scalar observation. It declares the
trusted interpreter and two worker assets and specifies the exact observed
source, function and ordered exact-bool input premises.

### [python_scalar_schema_v1.json](../_data/python_scalar_schema_v1.json)

Versioned Python scalar inspection report. It retains exact source, original
authority and context, resource profile, exchange identity, scoped native
body status and conditional output domain when available.
