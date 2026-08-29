//! Canonical language-neutral Program Semantic Model.
//!
//! The PSM records implementation facts only. It does not modify the CCG,
//! infer Intended BFG checkpoints, or claim function correctness.

#[path = "graph.rs"]
mod graph;
#[path = "rust.rs"]
mod rust;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::implementation_observation::{
    ImplementationObservationError, ImplementationObservationInput,
};

/// Registered PSM v3 schema identity.
pub const PROGRAM_SEMANTIC_MODEL_SCHEMA: &str = "urn:fortress:schema:v3:program-semantic-model";
/// Canonical PSM document schema version.
pub const PROGRAM_SEMANTIC_MODEL_SCHEMA_VERSION: u16 = 3;
/// Semantic version of the language-neutral PSM compiler.
pub const PROGRAM_SEMANTIC_MODEL_VERSION: &str = "3.0.0";
/// Stable Rust analyzer identity.
pub const RUST_PROGRAM_ANALYZER_ID: &str = "fortress-rust-program-semantics";
/// Semantic version of supported Rust program analysis.
pub const RUST_PROGRAM_ANALYZER_VERSION: &str = "3.0.0";

const UNSUPPORTED_SEMANTICS: &[&str] = &[
    "arbitrary_dynamic_dispatch_resolution",
    "authentication_authorization_state",
    "behavioral_realization",
    "capability_to_symbol_realization",
    "concurrency_interleaving_semantics",
    "full_alias_analysis",
    "general_effect_inference",
    "general_function_preconditions_postconditions",
    "heap_object_field_flow",
    "macro_generated_executable_semantics",
    "reflection",
    "refinement_value_ranges",
    "resource_typestate",
    "runtime_function_pointer_target_sets",
    "security_information_flow_proof",
    "semantic_units",
    "symbolic_execution",
    "taint_trust_state",
];

/// Immutable input for one snapshot-bound PSM compilation.
#[derive(Clone, Debug)]
pub struct ProgramSemanticInput {
    project_id: String,
    observation: ImplementationObservationInput,
    testing_modules: BTreeSet<String>,
    observed_module_dependencies: BTreeSet<(String, String)>,
}

impl ProgramSemanticInput {
    /// Creates one complete PSM input from canonical project and observation facts.
    #[must_use]
    pub fn new(
        project_id: impl Into<String>,
        observation: ImplementationObservationInput,
        testing_modules: impl IntoIterator<Item = String>,
        observed_module_dependencies: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        Self {
            project_id: project_id.into(),
            observation,
            testing_modules: testing_modules.into_iter().collect(),
            observed_module_dependencies: observed_module_dependencies.into_iter().collect(),
        }
    }

    pub(crate) fn project_id(&self) -> &str {
        &self.project_id
    }

    pub(crate) const fn observation(&self) -> &ImplementationObservationInput {
        &self.observation
    }

    pub(crate) const fn testing_modules(&self) -> &BTreeSet<String> {
        &self.testing_modules
    }

    pub(crate) const fn observed_module_dependencies(&self) -> &BTreeSet<(String, String)> {
        &self.observed_module_dependencies
    }
}

/// One analyzer implementation contributing facts to the PSM.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AnalyzerDescriptor {
    id: String,
    semantic_version: String,
    language: String,
    package_authority: String,
    declaration_authority: String,
    call_resolution_authority: String,
}

impl AnalyzerDescriptor {
    pub(crate) fn rust() -> Self {
        Self {
            id: RUST_PROGRAM_ANALYZER_ID.into(),
            semantic_version: RUST_PROGRAM_ANALYZER_VERSION.into(),
            language: "rust".into(),
            package_authority: "snapshot_bound_cargo_manifests".into(),
            declaration_authority: "structural_ast".into(),
            call_resolution_authority: "type_directed_structural".into(),
        }
    }
}

/// One governed Rust package and executable target context.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProgramPackage {
    name: String,
    manifest: String,
    targets: Vec<ProgramTarget>,
    workspace_dependencies: Vec<String>,
    external_dependencies: Vec<String>,
}

impl ProgramPackage {
    pub(crate) fn new(
        name: String,
        manifest: String,
        mut targets: Vec<ProgramTarget>,
        mut workspace_dependencies: Vec<String>,
        mut external_dependencies: Vec<String>,
    ) -> Self {
        targets.sort();
        targets.dedup();
        workspace_dependencies.sort();
        workspace_dependencies.dedup();
        external_dependencies.sort();
        external_dependencies.dedup();
        Self {
            name,
            manifest,
            targets,
            workspace_dependencies,
            external_dependencies,
        }
    }

    /// Returns the Cargo package name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// One Cargo target used as a Rust crate context.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProgramTarget {
    crate_name: String,
    kind: String,
    source_root: String,
}

impl ProgramTarget {
    pub(crate) fn new(crate_name: String, kind: String, source_root: String) -> Self {
        Self {
            crate_name,
            kind,
            source_root,
        }
    }
}

/// Executable symbol category independent of Rust syntax spelling.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableSymbolKind {
    /// Module-level executable function.
    FreeFunction,
    /// Inherent associated function without a receiver.
    AssociatedFunction,
    /// Inherent implementation method with a receiver.
    InherentMethod,
    /// Trait method signature without an implementation body.
    TraitMethodDeclaration,
    /// Method supplied by a trait implementation.
    TraitMethodImplementation,
}

/// Whether an executable belongs to production or canonical Testing territory.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolClassification {
    /// Executable owned by a production Module.
    Production,
    /// Executable owned by a CCG-identified Testing Module.
    Testing,
}

/// Language-neutral source visibility classification.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolVisibility {
    /// Visible only inside its immediate source scope.
    Private,
    /// Visible throughout the current crate.
    Crate,
    /// Publicly visible from the Rust crate surface.
    Public,
    /// Rust restricted visibility preserved verbatim.
    Restricted(String),
}

/// One exact source location in canonical repository coordinates.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProgramSourceLocation {
    line: u32,
    column: u32,
}

impl ProgramSourceLocation {
    /// Creates a stable one-based source location.
    #[must_use]
    pub const fn new(line: u32, column: u32) -> Self {
        Self { line, column }
    }

    /// Returns the one-based source line.
    #[must_use]
    pub const fn line(&self) -> u32 {
        self.line
    }

    /// Returns the one-based source column.
    #[must_use]
    pub const fn column(&self) -> u32 {
        self.column
    }
}

/// Language-neutral pattern used by observed control-flow structure.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProgramPattern {
    /// Pattern accepts every value.
    Wildcard,
    /// Pattern binds the matched value.
    Binding {
        /// Bound local identity.
        name: String,
    },
    /// Pattern selects one nominal or wrapper variant.
    Variant {
        /// Canonical source variant path.
        name: String,
        /// Nested payload patterns.
        fields: Vec<ProgramPattern>,
    },
    /// Ordered product pattern.
    Tuple {
        /// Nested component patterns.
        elements: Vec<ProgramPattern>,
    },
    /// Pattern semantics are not represented by PSM v3.
    Unsupported {
        /// Exact Rust pattern spelling.
        rust_spelling: String,
    },
}

/// Language-neutral expression structure required by later semantic consumers.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProgramExpression {
    /// Local binding reference.
    Binding {
        /// Binding identity.
        name: String,
    },
    /// Boolean literal.
    Boolean {
        /// Literal value.
        value: bool,
    },
    /// Integer literal retained without host-integer truncation.
    Integer {
        /// Canonical Rust literal spelling.
        value: String,
    },
    /// Unit value.
    Unit,
    /// Nominal variant or constant path.
    Variant {
        /// Canonical source path.
        name: String,
    },
    /// Ordered product expression.
    Tuple {
        /// Component expressions.
        elements: Vec<ProgramExpression>,
    },
    /// Direct field or tuple-field access with structured ownership.
    Field {
        /// Base value whose field is accessed.
        base: Box<ProgramExpression>,
        /// Named field or canonical tuple position.
        field: String,
    },
    /// Wrapper or nominal construction.
    Construction {
        /// Constructor path.
        constructor: String,
        /// Constructed payloads.
        arguments: Vec<ProgramExpression>,
    },
    /// Pattern-directed predicate such as Rust `if let`.
    PatternTest {
        /// Admission pattern.
        pattern: ProgramPattern,
        /// Value tested by the pattern.
        value: Box<ProgramExpression>,
    },
    /// Function or associated-function invocation.
    Call {
        /// Source reference used for PSM call-site correlation.
        reference: String,
        /// Ordered argument expressions.
        arguments: Vec<ProgramExpression>,
    },
    /// Receiver-style method invocation.
    MethodCall {
        /// Receiver expression.
        receiver: Box<ProgramExpression>,
        /// Method name.
        method: String,
        /// Ordered explicit arguments.
        arguments: Vec<ProgramExpression>,
    },
    /// Binary operation.
    Binary {
        /// Canonical operator spelling.
        operator: String,
        /// Left operand.
        left: Box<ProgramExpression>,
        /// Right operand.
        right: Box<ProgramExpression>,
    },
    /// Unary operation.
    Unary {
        /// Canonical operator spelling.
        operator: String,
        /// Operand.
        value: Box<ProgramExpression>,
    },
    /// Rust `?` propagation.
    Try {
        /// Propagated expression.
        value: Box<ProgramExpression>,
    },
    /// Shared or mutable reference construction.
    Reference {
        /// Whether mutation is permitted.
        mutable: bool,
        /// Referenced expression.
        value: Box<ProgramExpression>,
    },
    /// A recognized exceptional macro site.
    Exceptional {
        /// Stable exceptional operation identity.
        operation: String,
    },
    /// Expression semantics are not represented by PSM v3.
    Unsupported {
        /// Exact Rust expression spelling.
        rust_spelling: String,
    },
}

/// Structured assignable/readable program location.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProgramPlace {
    /// Local binding, including the canonical `self` receiver binding.
    Binding {
        /// Binding identity.
        name: String,
        /// Static type identity when established.
        static_type: Option<String>,
    },
    /// Direct named field of a supported place.
    Field {
        /// Structured base place.
        base: Box<ProgramPlace>,
        /// Resolved local nominal owner identity when known.
        nominal_owner: Option<String>,
        /// Source field identity.
        field: String,
        /// Static field type identity when established.
        static_type: Option<String>,
    },
    /// Direct positional field of a supported place.
    TupleField {
        /// Structured base place.
        base: Box<ProgramPlace>,
        /// Zero-based tuple field position.
        position: usize,
        /// Static field type identity when established.
        static_type: Option<String>,
    },
    /// Explicit dereference whose alias identity is not necessarily proven.
    Dereference {
        /// Referenced place.
        base: Box<ProgramPlace>,
        /// Static dereferenced type identity when established.
        static_type: Option<String>,
    },
    /// Place syntax outside the structured v3 boundary.
    Unsupported {
        /// Exact Rust spelling retained for coverage explanation.
        rust_spelling: String,
    },
}

impl ProgramPlace {
    /// Returns whether this place is rooted in the current receiver.
    #[must_use]
    pub fn is_receiver(&self) -> bool {
        match self {
            Self::Binding { name, .. } => name == "self",
            Self::Field { base, .. }
            | Self::TupleField { base, .. }
            | Self::Dereference { base, .. } => base.is_receiver(),
            Self::Unsupported { .. } => false,
        }
    }

    /// Returns the direct field identity when this is a field place.
    #[must_use]
    pub fn field_name(&self) -> Option<&str> {
        match self {
            Self::Field { field, .. } => Some(field),
            Self::TupleField { .. }
            | Self::Binding { .. }
            | Self::Dereference { .. }
            | Self::Unsupported { .. } => None,
        }
    }

    /// Returns the root binding identity when structurally available.
    #[must_use]
    pub fn root_binding(&self) -> Option<&str> {
        match self {
            Self::Binding { name, .. } => Some(name),
            Self::Field { base, .. }
            | Self::TupleField { base, .. }
            | Self::Dereference { base, .. } => base.root_binding(),
            Self::Unsupported { .. } => None,
        }
    }

    /// Returns the exact static type identity when attached to this place.
    #[must_use]
    pub fn static_type(&self) -> Option<&str> {
        match self {
            Self::Binding { static_type, .. }
            | Self::Field { static_type, .. }
            | Self::TupleField { static_type, .. }
            | Self::Dereference { static_type, .. } => static_type.as_deref(),
            Self::Unsupported { .. } => None,
        }
    }

    /// Returns the local nominal field-owner identity when resolved.
    #[must_use]
    pub fn nominal_owner(&self) -> Option<&str> {
        match self {
            Self::Field { nominal_owner, .. } => nominal_owner.as_deref(),
            _ => None,
        }
    }
}

/// Supported mutation category emitted without safety interpretation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    /// Direct assignment with `=`.
    Assignment,
    /// Compound assignment such as `+=`.
    CompoundAssignment,
    /// Direct update of a mutable named or tuple field.
    MutableFieldUpdate,
}

/// Confidence of one structured state-access or mutation fact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlaceResolutionState {
    /// Binding and field identity are structurally exact.
    ResolvedExact,
    /// The place is supported but its nominal/static type is incomplete.
    TypeUnknown,
    /// Alias or dereference semantics prevent exact identity.
    AliasUnknown,
    /// Place syntax is outside the implemented boundary.
    Unsupported,
}

/// One structured state read observed in an executable body.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct StateRead {
    id: String,
    symbol: String,
    place: ProgramPlace,
    resolution: PlaceResolutionState,
    provenance: ProgramProvenance,
}

impl StateRead {
    /// Returns the executable containing the read.
    #[must_use]
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    /// Returns the structured read place.
    #[must_use]
    pub const fn place(&self) -> &ProgramPlace {
        &self.place
    }

    /// Returns exact source provenance.
    #[must_use]
    pub const fn provenance(&self) -> &ProgramProvenance {
        &self.provenance
    }
}

/// One structured mutation observed in an executable body.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProgramMutation {
    id: String,
    symbol: String,
    target: ProgramPlace,
    mutation_kind: MutationKind,
    value: ProgramExpression,
    value_type: Option<String>,
    resolution: PlaceResolutionState,
    provenance: ProgramProvenance,
}

impl ProgramMutation {
    /// Returns the executable containing the mutation.
    #[must_use]
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    /// Returns the structured target place.
    #[must_use]
    pub const fn target(&self) -> &ProgramPlace {
        &self.target
    }

    /// Returns the assigned value expression.
    #[must_use]
    pub const fn value(&self) -> &ProgramExpression {
        &self.value
    }

    /// Returns the mutation category.
    #[must_use]
    pub const fn mutation_kind(&self) -> MutationKind {
        self.mutation_kind
    }

    /// Returns source provenance.
    #[must_use]
    pub const fn provenance(&self) -> &ProgramProvenance {
        &self.provenance
    }
}

/// One observed branch of a Rust match expression.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProgramMatchArm {
    pattern: ProgramPattern,
    guard: Option<ProgramExpression>,
    body: Vec<ProgramStatement>,
    provenance: ProgramProvenance,
}

impl ProgramMatchArm {
    /// Returns the arm admission pattern.
    #[must_use]
    pub const fn pattern(&self) -> &ProgramPattern {
        &self.pattern
    }

    /// Returns the optional guard expression.
    #[must_use]
    pub const fn guard(&self) -> Option<&ProgramExpression> {
        self.guard.as_ref()
    }

    /// Returns the arm statements.
    #[must_use]
    pub fn body(&self) -> &[ProgramStatement] {
        &self.body
    }

    /// Returns source provenance for the arm.
    #[must_use]
    pub const fn provenance(&self) -> &ProgramProvenance {
        &self.provenance
    }
}

/// Language-neutral statement/control structure emitted by the PSM analyzer.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProgramStatement {
    /// Local binding initialization.
    Let {
        /// Bound pattern.
        pattern: ProgramPattern,
        /// Initial value when present.
        value: Option<ProgramExpression>,
        /// Exact source provenance.
        provenance: ProgramProvenance,
    },
    /// Assignment to one supported place expression.
    Assign {
        /// Exact target spelling retained for the value-domain interpreter.
        target: String,
        /// Assigned value.
        value: ProgramExpression,
        /// Exact source provenance.
        provenance: ProgramProvenance,
    },
    /// Standalone expression.
    Expression {
        /// Expression structure.
        value: ProgramExpression,
        /// Exact source provenance.
        provenance: ProgramProvenance,
    },
    /// Function return contribution.
    Return {
        /// Returned expression; absent for unit return.
        value: Option<ProgramExpression>,
        /// Exact source provenance.
        provenance: ProgramProvenance,
    },
    /// Conditional control-flow split.
    If {
        /// Branch predicate.
        condition: ProgramExpression,
        /// Statements evaluated when true.
        then_branch: Vec<ProgramStatement>,
        /// Statements evaluated when false.
        else_branch: Vec<ProgramStatement>,
        /// Exact source provenance.
        provenance: ProgramProvenance,
    },
    /// Pattern-directed control-flow split.
    Match {
        /// Matched value.
        value: ProgramExpression,
        /// Ordered source arms.
        arms: Vec<ProgramMatchArm>,
        /// Exact source provenance.
        provenance: ProgramProvenance,
    },
    /// Pattern-directed loop.
    WhileLet {
        /// Loop admission pattern.
        pattern: ProgramPattern,
        /// Re-evaluated source expression.
        value: ProgramExpression,
        /// Loop body.
        body: Vec<ProgramStatement>,
        /// Exact source provenance.
        provenance: ProgramProvenance,
    },
}

/// One executable body represented as observed control/value structure.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProgramBody {
    symbol: String,
    statements: Vec<ProgramStatement>,
    provenance: ProgramProvenance,
}

impl ProgramBody {
    /// Returns the owning executable symbol identity.
    #[must_use]
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    /// Returns canonical observed statements.
    #[must_use]
    pub fn statements(&self) -> &[ProgramStatement] {
        &self.statements
    }
}

/// Exact source provenance for a PSM source fact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProgramProvenance {
    path: String,
    location: ProgramSourceLocation,
    symbol_context: Option<String>,
    analyzer: String,
    analyzer_semantic_version: String,
}

impl ProgramProvenance {
    pub(crate) fn rust(
        path: impl Into<String>,
        location: ProgramSourceLocation,
        symbol_context: Option<String>,
    ) -> Self {
        Self {
            path: path.into(),
            location,
            symbol_context,
            analyzer: RUST_PROGRAM_ANALYZER_ID.into(),
            analyzer_semantic_version: RUST_PROGRAM_ANALYZER_VERSION.into(),
        }
    }

    /// Returns the canonical repository-relative source path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the stable source location.
    #[must_use]
    pub const fn location(&self) -> &ProgramSourceLocation {
        &self.location
    }
}

/// Language-neutral recursive static type representation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SemanticType {
    /// Rust unit type.
    Unit,
    /// Rust never type.
    Never,
    /// Boolean value.
    Bool,
    /// Signed or unsigned integer family.
    Integer {
        /// Exact Rust integer family or explicit inferred-literal class.
        family: String,
    },
    /// Floating-point family.
    Float {
        /// Exact Rust floating family or explicit inferred-literal class.
        family: String,
    },
    /// Unicode scalar value.
    Char,
    /// Owned or borrowed string representation.
    String {
        /// Owned, borrowed, or language-defined string representation.
        representation: String,
    },
    /// Ordered product type.
    Tuple {
        /// Ordered element types.
        elements: Vec<SemanticType>,
    },
    /// Fixed-length homogeneous aggregate.
    Array {
        /// Homogeneous element type.
        element: Box<SemanticType>,
        /// Canonical Rust length expression.
        length: String,
    },
    /// Dynamically sized homogeneous view.
    Slice {
        /// Homogeneous element type.
        element: Box<SemanticType>,
    },
    /// Shared or mutable reference.
    Reference {
        /// Whether the reference permits mutation.
        mutable: bool,
        /// Declared lifetime when explicitly represented.
        lifetime: Option<String>,
        /// Referenced type.
        target: Box<SemanticType>,
    },
    /// Raw pointer.
    Pointer {
        /// Whether the raw pointer is mutable.
        mutable: bool,
        /// Pointed-to type.
        target: Box<SemanticType>,
    },
    /// Nominal language type.
    Named {
        /// Canonical nominal path spelling without generic arguments.
        name: String,
        /// Normalized generic type arguments.
        arguments: Vec<SemanticType>,
    },
    /// Function generic type parameter.
    GenericParameter {
        /// Declared generic parameter identity.
        name: String,
    },
    /// Optional value wrapper preserved semantically.
    Option {
        /// Wrapped value type.
        value: Box<SemanticType>,
    },
    /// Success/error wrapper preserved semantically.
    Result {
        /// Success value type.
        success: Box<SemanticType>,
        /// Error value type.
        error: Box<SemanticType>,
    },
    /// Statically declared function type.
    Function {
        /// Declared function input types.
        parameters: Vec<SemanticType>,
        /// Declared function result type.
        result: Box<SemanticType>,
    },
    /// Syntax whose exact static type semantics are outside v1.
    Unknown {
        /// Exact Rust spelling retained for unsupported type semantics.
        rust_spelling: String,
    },
}

/// Canonical deduplicated static type fact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProgramType {
    id: String,
    language: String,
    semantic: SemanticType,
    rust_spellings: Vec<String>,
}

impl ProgramType {
    pub(crate) fn new(id: String, semantic: SemanticType, mut rust_spellings: Vec<String>) -> Self {
        rust_spellings.sort();
        rust_spellings.dedup();
        Self {
            id,
            language: "rust".into(),
            semantic,
            rust_spellings,
        }
    }

    /// Returns the deterministic type identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the language-neutral type shape.
    #[must_use]
    pub const fn semantic(&self) -> &SemanticType {
        &self.semantic
    }
}

/// Kind of a locally governed nominal type declaration.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NominalTypeKind {
    /// A Rust record or tuple structure.
    Struct,
    /// A Rust sum type.
    Enum,
    /// A Rust trait declaration.
    Trait,
    /// A Rust type alias.
    TypeAlias,
}

/// One named or positional field owned by a nominal declaration.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NominalField {
    name: String,
    position: usize,
    field_type: InterfaceType,
    provenance: ProgramProvenance,
}

impl NominalField {
    /// Returns the declared field identity.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the field's normalized static type.
    #[must_use]
    pub const fn field_type(&self) -> &InterfaceType {
        &self.field_type
    }
}

/// One enum variant and its supported payload fields.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NominalVariant {
    name: String,
    fields: Vec<NominalField>,
    provenance: ProgramProvenance,
}

/// One source-authored local nominal type declaration.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NominalType {
    id: String,
    qualified_name: String,
    language: String,
    package: String,
    crate_name: String,
    rust_module: String,
    fortress_module: String,
    kind: NominalTypeKind,
    generic_parameters: Vec<String>,
    fields: Vec<NominalField>,
    variants: Vec<NominalVariant>,
    trait_methods: Vec<String>,
    alias_target: Option<InterfaceType>,
    alias_transparent: bool,
    provenance: ProgramProvenance,
}

impl NominalType {
    /// Returns the stable derived nominal identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the source-qualified nominal name.
    #[must_use]
    pub fn qualified_name(&self) -> &str {
        &self.qualified_name
    }

    /// Returns the declaration kind.
    #[must_use]
    pub const fn kind(&self) -> NominalTypeKind {
        self.kind
    }

    /// Returns the physical Fortress Module owner.
    #[must_use]
    pub fn fortress_module(&self) -> &str {
        &self.fortress_module
    }

    /// Returns direct nominal fields.
    #[must_use]
    pub fn fields(&self) -> &[NominalField] {
        &self.fields
    }

    /// Returns exact declaration provenance for this nominal type.
    #[must_use]
    pub const fn provenance(&self) -> &ProgramProvenance {
        &self.provenance
    }
}

/// Kind of a Rust implementation block.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramImplKind {
    /// Methods implemented directly for one type.
    Inherent,
    /// Methods implementing one trait for one type.
    Trait,
}

/// Resolution state of one implementation block's type identities.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImplResolutionState {
    /// Self and optional trait identities resolve to local declarations.
    ResolvedLocal,
    /// At least one identity is external or generic.
    ExternalOrGeneric,
    /// Supported syntax could not establish one exact identity.
    Unresolved,
}

/// One source-authored Rust implementation block.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProgramImpl {
    id: String,
    package: String,
    crate_name: String,
    rust_module: String,
    fortress_module: String,
    kind: ProgramImplKind,
    self_type: InterfaceType,
    trait_type: Option<InterfaceType>,
    generic_parameters: Vec<String>,
    methods: Vec<String>,
    resolution: ImplResolutionState,
    provenance: ProgramProvenance,
}

/// One type use at an executable interface.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct InterfaceType {
    type_id: String,
    rust_spelling: String,
    resolution: TypeResolution,
}

impl InterfaceType {
    pub(crate) fn new(type_id: String, rust_spelling: String, resolution: TypeResolution) -> Self {
        Self {
            type_id,
            rust_spelling,
            resolution,
        }
    }

    /// Returns the referenced canonical type identity.
    #[must_use]
    pub fn type_id(&self) -> &str {
        &self.type_id
    }
}

/// Confidence of one normalized interface type.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TypeResolution {
    /// Type is exact from an explicit Rust signature.
    DeclaredExact,
    /// Type syntax is preserved but its semantic form is unsupported.
    Unsupported,
}

/// One executable parameter.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProgramParameter {
    position: usize,
    name: String,
    parameter_type: InterfaceType,
    provenance: ProgramProvenance,
}

impl ProgramParameter {
    pub(crate) fn new(
        position: usize,
        name: String,
        parameter_type: InterfaceType,
        provenance: ProgramProvenance,
    ) -> Self {
        Self {
            position,
            name,
            parameter_type,
            provenance,
        }
    }

    /// Returns the zero-based parameter position.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Returns the normalized parameter type reference.
    #[must_use]
    pub const fn parameter_type(&self) -> &InterfaceType {
        &self.parameter_type
    }

    /// Returns the source parameter identity.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns exact parameter declaration provenance.
    #[must_use]
    pub const fn provenance(&self) -> &ProgramProvenance {
        &self.provenance
    }
}

/// Optional Rust receiver semantics for one method.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProgramReceiver {
    mutable: bool,
    by_reference: bool,
    explicit_type: Option<InterfaceType>,
}

impl ProgramReceiver {
    pub(crate) const fn new(
        mutable: bool,
        by_reference: bool,
        explicit_type: Option<InterfaceType>,
    ) -> Self {
        Self {
            mutable,
            by_reference,
            explicit_type,
        }
    }

    /// Returns whether the receiver permits mutation.
    #[must_use]
    pub const fn is_mutable(&self) -> bool {
        self.mutable
    }

    /// Returns whether the receiver is borrowed.
    #[must_use]
    pub const fn is_by_reference(&self) -> bool {
        self.by_reference
    }
}

/// Rust declaration qualifiers retained independently from the neutral symbol kind.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SymbolQualifiers {
    is_async: bool,
    is_unsafe: bool,
    is_const: bool,
}

impl SymbolQualifiers {
    pub(crate) const fn new(is_async: bool, is_unsafe: bool, is_const: bool) -> Self {
        Self {
            is_async,
            is_unsafe,
            is_const,
        }
    }

    /// Returns whether the declaration is unsafe.
    #[must_use]
    pub const fn is_unsafe(self) -> bool {
        self.is_unsafe
    }
}

/// Whether an executable symbol is only declared or has an analyzable body.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SymbolBodyState {
    /// No executable body is present in the observed source.
    Declaration,
    /// The observed source contains an executable body.
    Definition,
}

/// One deterministic executable symbol fact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ExecutableSymbol {
    id: String,
    qualified_name: String,
    language: String,
    package: String,
    crate_name: String,
    rust_module: String,
    fortress_module: String,
    classification: SymbolClassification,
    source_path: String,
    kind: ExecutableSymbolKind,
    owner_type: Option<String>,
    owner_trait: Option<String>,
    parameters: Vec<ProgramParameter>,
    return_type: InterfaceType,
    receiver: Option<ProgramReceiver>,
    generic_parameters: Vec<String>,
    lifetimes: Vec<String>,
    qualifiers: SymbolQualifiers,
    visibility: SymbolVisibility,
    body_state: SymbolBodyState,
    provenance: ProgramProvenance,
}

impl ExecutableSymbol {
    /// Returns the deterministic semantic symbol identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the human-readable Rust qualified name.
    #[must_use]
    pub fn qualified_name(&self) -> &str {
        &self.qualified_name
    }

    #[must_use]
    pub(crate) fn has_body(&self) -> bool {
        self.body_state == SymbolBodyState::Definition
    }

    /// Returns the physical Fortress Module owner.
    #[must_use]
    pub fn fortress_module(&self) -> &str {
        &self.fortress_module
    }

    /// Returns the canonical source file path.
    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    /// Returns exact declaration provenance for this executable symbol.
    #[must_use]
    pub const fn provenance(&self) -> &ProgramProvenance {
        &self.provenance
    }

    /// Returns the production or Testing classification.
    #[must_use]
    pub const fn classification(&self) -> SymbolClassification {
        self.classification
    }

    /// Returns the executable category.
    #[must_use]
    pub const fn kind(&self) -> ExecutableSymbolKind {
        self.kind
    }

    /// Returns the executable parameters.
    #[must_use]
    pub fn parameters(&self) -> &[ProgramParameter] {
        &self.parameters
    }

    /// Returns the normalized result type.
    #[must_use]
    pub const fn return_type(&self) -> &InterfaceType {
        &self.return_type
    }

    /// Returns optional receiver semantics.
    #[must_use]
    pub const fn receiver(&self) -> Option<&ProgramReceiver> {
        self.receiver.as_ref()
    }

    /// Returns the source owner type spelling for a method.
    #[must_use]
    pub fn owner_type(&self) -> Option<&str> {
        self.owner_type.as_deref()
    }

    /// Returns retained declaration qualifiers.
    #[must_use]
    pub const fn qualifiers(&self) -> SymbolQualifiers {
        self.qualifiers
    }

    /// Returns the observed language-neutral visibility.
    #[must_use]
    pub const fn visibility(&self) -> &SymbolVisibility {
        &self.visibility
    }
}

/// Resolution state assigned to every relevant call expression.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CallResolutionState {
    /// Exact governed callee resolved under supported static semantics.
    ResolvedStatic,
    /// Call target is outside the governed package ecosystem.
    External,
    /// Runtime dispatch prevents one exact target.
    DynamicDispatch,
    /// Supported syntax did not resolve confidently.
    Unresolved,
    /// Required semantics are outside PSM v3.
    Unsupported,
    /// Source or model violated a supported analyzer invariant.
    Invalid,
}

/// Stable semantic explanation for a non-static call classification.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CallResolutionReason {
    /// The receiver's exact static type was not established.
    UnknownReceiverType,
    /// More than one local method remained applicable.
    AmbiguousLocalMethod,
    /// The receiver remains a generic parameter.
    GenericReceiver,
    /// A trait-object call requires runtime dispatch.
    TraitObjectDispatch,
    /// Trait selection was not uniquely provable.
    UnresolvedTraitSelection,
    /// The receiver is known to be owned outside the governed workspace.
    ExternalReceiver,
    /// User-defined dereference semantics are outside v2.
    UnsupportedDeref,
    /// Executable semantics originate from a macro invocation.
    MacroGenerated,
    /// The target is a function-valued expression.
    FunctionPointer,
    /// The target is a closure without a stable executable identity.
    ClosureTarget,
    /// The syntax belongs to an unimplemented v2 semantic class.
    UnsupportedSyntax,
    /// A supported path did not resolve to a known target.
    UnknownPath,
}

/// Semantic authority used for a call classification.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionAuthority {
    /// Package/crate classification came from snapshot-bound Cargo manifest semantics.
    CargoManifest,
    /// Exact target followed a unique structural declaration path.
    StructuralExact,
    /// Exact target followed receiver-type and implementation-index semantics.
    TypeDirectedExact,
    /// Exact external ownership was established without analyzing its body.
    ExactExternalOwner,
    /// Runtime selection is represented by a sound candidate set.
    ConservativeCandidateSet,
    /// Supported syntax lacked sufficient static type information.
    InsufficientTypeInformation,
    /// A sound conservative class was established without one exact target.
    Conservative,
    /// No implemented semantic authority covers the construct.
    Unsupported,
}

/// One exact call-site observation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CallSiteEvidence {
    reference: String,
    argument_count: usize,
    receiver: Option<ProgramPlace>,
    provenance: ProgramProvenance,
}

impl CallSiteEvidence {
    pub(crate) fn new(
        reference: String,
        argument_count: usize,
        provenance: ProgramProvenance,
    ) -> Self {
        Self {
            reference,
            argument_count,
            receiver: None,
            provenance,
        }
    }

    pub(crate) fn with_receiver(mut self, receiver: ProgramPlace) -> Self {
        self.receiver = Some(receiver);
        self
    }
}

/// One normalized call relation or explicit unresolved call class.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProgramCall {
    id: String,
    caller: String,
    state: CallResolutionState,
    authority: ResolutionAuthority,
    reason: Option<CallResolutionReason>,
    callee: Option<String>,
    boundary_target_module: Option<String>,
    external_target: Option<String>,
    candidate_callees: Vec<String>,
    evidence: Vec<CallSiteEvidence>,
}

impl ProgramCall {
    /// Returns the caller identity.
    #[must_use]
    pub fn caller(&self) -> &str {
        &self.caller
    }

    /// Returns the exact callee when statically resolved.
    #[must_use]
    pub fn callee(&self) -> Option<&str> {
        self.callee.as_deref()
    }

    /// Returns the call resolution state.
    #[must_use]
    pub const fn state(&self) -> CallResolutionState {
        self.state
    }

    /// Returns the stable residual-resolution reason, when applicable.
    #[must_use]
    pub const fn reason(&self) -> Option<CallResolutionReason> {
        self.reason
    }

    /// Returns supporting call sites.
    #[must_use]
    pub fn evidence(&self) -> &[CallSiteEvidence] {
        &self.evidence
    }
}

impl CallSiteEvidence {
    /// Returns the source reference spelling.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Returns exact call-site provenance.
    #[must_use]
    pub const fn provenance(&self) -> &ProgramProvenance {
        &self.provenance
    }

    /// Returns the structured receiver place for a method call.
    #[must_use]
    pub const fn receiver(&self) -> Option<&ProgramPlace> {
        self.receiver.as_ref()
    }
}

/// Initial value-transfer category supported by PSM v3.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueTransferKind {
    /// Function parameter enters its local binding.
    ParameterToBinding,
    /// Expression initializes or updates a local binding.
    ExpressionToBinding,
    /// Assignment moves a value to a place expression.
    Assignment,
    /// Expression contributes to the function result.
    ExpressionToReturn,
    /// Call argument corresponds to one callee parameter.
    ArgumentToParameter,
    /// Callee result enters a receiving binding or expression.
    ReturnToConsumer,
}

/// Resolution state for a bounded value-transfer fact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferResolutionState {
    /// Transfer follows explicit supported syntax.
    SyntaxExact,
    /// Transfer is linked through one resolved static call.
    ResolvedStaticCall,
    /// Transfer exists but its exact static type is unknown.
    TypeUnknown,
    /// Required transfer semantics are outside PSM v3.
    Unsupported,
}

/// One value producer or consumer endpoint.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ValueEndpoint {
    symbol: String,
    role: String,
    name: String,
    static_type: Option<String>,
}

impl ValueEndpoint {
    pub(crate) fn new(
        symbol: String,
        role: impl Into<String>,
        name: impl Into<String>,
        static_type: Option<String>,
    ) -> Self {
        Self {
            symbol,
            role: role.into(),
            name: name.into(),
            static_type,
        }
    }

    /// Returns the endpoint's executable symbol.
    #[must_use]
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    /// Returns the endpoint semantic role.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Returns the endpoint-local identity or source expression.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the PSM static type identity when known.
    #[must_use]
    pub fn static_type(&self) -> Option<&str> {
        self.static_type.as_deref()
    }
}

/// One bounded source-level value transfer.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ValueTransfer {
    id: String,
    kind: ValueTransferKind,
    producer: ValueEndpoint,
    consumer: ValueEndpoint,
    resolution: TransferResolutionState,
    provenance: ProgramProvenance,
}

impl ValueTransfer {
    /// Returns the transfer category.
    #[must_use]
    pub const fn kind(&self) -> ValueTransferKind {
        self.kind
    }

    /// Returns the producing endpoint.
    #[must_use]
    pub const fn producer(&self) -> &ValueEndpoint {
        &self.producer
    }

    /// Returns the consuming endpoint.
    #[must_use]
    pub const fn consumer(&self) -> &ValueEndpoint {
        &self.consumer
    }

    /// Returns exact transfer provenance.
    #[must_use]
    pub const fn provenance(&self) -> &ProgramProvenance {
        &self.provenance
    }
}

/// Explicit type/value transformation category retained for later domain analysis.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformationKind {
    /// Nominal or aggregate value construction.
    Construction,
    /// Pattern destructuring.
    Destructuring,
    /// Rust `as` cast.
    Cast,
    /// Explicit conversion call such as `into` or `from`.
    ConversionCall,
    /// Optional-value construction or extraction.
    OptionTransition,
    /// Result construction or propagation.
    ResultTransition,
    /// Pattern-mediated narrowing.
    PatternNarrowing,
    /// Reference or mutability transition.
    ReferenceTransition,
}

/// One explicit source transformation fact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TypeTransformation {
    id: String,
    symbol: String,
    kind: TransformationKind,
    source_type: Option<String>,
    target_type: Option<String>,
    provenance: ProgramProvenance,
}

/// One resolved call that crosses physical Fortress Module territory.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CrossModuleCall {
    caller: String,
    callee: String,
    source_module: String,
    target_module: String,
    callee_module: String,
    call: String,
    evidence: Vec<CallSiteEvidence>,
}

/// One call strongly connected component.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CallComponent {
    id: String,
    symbols: Vec<String>,
    recursive: bool,
}

/// Deterministic call graph derivations over resolved static calls only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CallTopology {
    direct_callees: BTreeMap<String, Vec<String>>,
    direct_callers: BTreeMap<String, Vec<String>>,
    transitive_reachability: BTreeMap<String, Vec<String>>,
    strongly_connected_components: Vec<CallComponent>,
    recursive_symbols: Vec<String>,
    entry_candidates: Vec<String>,
    leaf_symbols: Vec<String>,
    cross_package_calls: Vec<String>,
}

impl CallTopology {
    /// Returns recursive call components, including direct recursion.
    #[must_use]
    pub fn strongly_connected_components(&self) -> &[CallComponent] {
        &self.strongly_connected_components
    }
}

impl CallComponent {
    /// Returns whether this component represents direct or mutual recursion.
    #[must_use]
    pub const fn is_recursive(&self) -> bool {
        self.recursive
    }
}

/// Analyzer agreement between PSM call projection and Implementation Observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnalyzerCoherency {
    status: String,
    checked_cross_module_calls: usize,
    missing_observation_edges: Vec<String>,
}

impl AnalyzerCoherency {
    /// Returns whether all resolved cross-Module calls have observation support.
    #[must_use]
    pub fn is_coherent(&self) -> bool {
        self.status == "coherent"
    }
}

/// Aggregate exact coverage counts for one PSM document.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ProgramCoverage {
    source_files: usize,
    packages: usize,
    executable_symbols: usize,
    nominal_types: usize,
    nominal_structs: usize,
    nominal_enums: usize,
    nominal_traits: usize,
    nominal_type_aliases: usize,
    nominal_fields: usize,
    nominal_variants: usize,
    impls: usize,
    production_symbols: usize,
    testing_symbols: usize,
    free_functions: usize,
    associated_functions: usize,
    inherent_methods: usize,
    trait_method_declarations: usize,
    trait_method_implementations: usize,
    resolved_static_calls: usize,
    external_calls: usize,
    dynamic_dispatch_calls: usize,
    unresolved_calls: usize,
    unsupported_calls: usize,
    invalid_calls: usize,
    cross_module_calls: usize,
    cross_package_calls: usize,
    recursive_components: usize,
    value_transfers: usize,
    transformations: usize,
    state_reads: usize,
    mutations: usize,
    resolved_mutations: usize,
    uncertain_mutations: usize,
}

/// Aggregate call-resolution states and stable residual reasons.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolutionSummary {
    resolved_static: usize,
    external: usize,
    dynamic_dispatch: usize,
    unresolved: usize,
    unsupported: usize,
    invalid: usize,
    reasons: BTreeMap<String, usize>,
    fixed_point_iterations: usize,
}

impl ProgramCoverage {
    /// Returns the number of executable symbols.
    #[must_use]
    pub const fn executable_symbols(self) -> usize {
        self.executable_symbols
    }

    /// Returns the number of invalid calls.
    #[must_use]
    pub const fn invalid_calls(self) -> usize {
        self.invalid_calls
    }

    /// Returns the resolved static call count.
    #[must_use]
    pub const fn resolved_static_calls(self) -> usize {
        self.resolved_static_calls
    }
}

/// One exact semantic source input participating in PSM identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProgramSourceInput {
    path: String,
    sha256: String,
}

/// Canonical PSM provenance envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProgramModelProvenance {
    identity_kind: String,
    semantic_inputs: Vec<ProgramSourceInput>,
    ownership_authority: String,
    testing_authority: String,
}

/// Canonical Program Semantic Model v3 document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProgramSemanticModel {
    #[serde(rename = "$schema")]
    schema: String,
    schema_version: u16,
    semantic_version: String,
    project_id: String,
    source_identity: String,
    analyzers: Vec<AnalyzerDescriptor>,
    languages: Vec<String>,
    packages: Vec<ProgramPackage>,
    nominal_types: Vec<NominalType>,
    impls: Vec<ProgramImpl>,
    symbols: Vec<ExecutableSymbol>,
    types: Vec<ProgramType>,
    calls: Vec<ProgramCall>,
    bodies: Vec<ProgramBody>,
    value_transfers: Vec<ValueTransfer>,
    transformations: Vec<TypeTransformation>,
    state_reads: Vec<StateRead>,
    mutations: Vec<ProgramMutation>,
    module_boundaries: Vec<CrossModuleCall>,
    call_topology: CallTopology,
    resolution_summary: ResolutionSummary,
    coverage: ProgramCoverage,
    analyzer_coherency: AnalyzerCoherency,
    unsupported_semantics: Vec<String>,
    provenance: ProgramModelProvenance,
}

impl ProgramSemanticModel {
    /// Returns the governed project identity.
    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Returns the exact semantic input identity.
    #[must_use]
    pub fn source_identity(&self) -> &str {
        &self.source_identity
    }

    /// Returns all executable symbols in canonical order.
    #[must_use]
    pub fn symbols(&self) -> &[ExecutableSymbol] {
        &self.symbols
    }

    /// Returns locally governed nominal declarations.
    #[must_use]
    pub fn nominal_types(&self) -> &[NominalType] {
        &self.nominal_types
    }

    /// Returns source implementation blocks.
    #[must_use]
    pub fn impls(&self) -> &[ProgramImpl] {
        &self.impls
    }

    /// Returns all normalized calls and explicit coverage states.
    #[must_use]
    pub fn calls(&self) -> &[ProgramCall] {
        &self.calls
    }

    /// Returns observed executable body structure.
    #[must_use]
    pub fn bodies(&self) -> &[ProgramBody] {
        &self.bodies
    }

    /// Returns normalized static types.
    #[must_use]
    pub fn types(&self) -> &[ProgramType] {
        &self.types
    }

    /// Returns bounded value-transfer facts.
    #[must_use]
    pub fn value_transfers(&self) -> &[ValueTransfer] {
        &self.value_transfers
    }

    /// Returns structured field/state reads.
    #[must_use]
    pub fn state_reads(&self) -> &[StateRead] {
        &self.state_reads
    }

    /// Returns structured mutations.
    #[must_use]
    pub fn mutations(&self) -> &[ProgramMutation] {
        &self.mutations
    }

    /// Returns cross-Module static calls.
    #[must_use]
    pub fn module_boundaries(&self) -> &[CrossModuleCall] {
        &self.module_boundaries
    }

    /// Returns deterministic call-graph derivations.
    #[must_use]
    pub const fn call_topology(&self) -> &CallTopology {
        &self.call_topology
    }

    /// Returns aggregate coverage counts.
    #[must_use]
    pub const fn coverage(&self) -> ProgramCoverage {
        self.coverage
    }

    /// Returns analyzer-projection coherency.
    #[must_use]
    pub const fn analyzer_coherency(&self) -> &AnalyzerCoherency {
        &self.analyzer_coherency
    }

    /// Returns explicit unsupported semantic classes.
    #[must_use]
    pub fn unsupported_semantics(&self) -> &[String] {
        &self.unsupported_semantics
    }

    /// Serializes canonical UTF-8 JSON with two-space indentation and one LF.
    ///
    /// # Errors
    ///
    /// Returns an error when the in-memory model cannot be serialized.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        let mut document = serde_json::to_string_pretty(self)?;
        document.push('\n');
        Ok(document)
    }

    /// Computes SHA-256 over canonical serialized bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical serialization fails.
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        Ok(format!(
            "sha256:{:x}",
            Sha256::digest(self.to_canonical_json()?.as_bytes())
        ))
    }
}

pub(crate) struct RustProgramFacts {
    source_identity: String,
    source_inputs: Vec<ProgramSourceInput>,
    source_files: usize,
    packages: Vec<ProgramPackage>,
    nominal_types: Vec<NominalType>,
    impls: Vec<ProgramImpl>,
    symbols: Vec<ExecutableSymbol>,
    types: Vec<ProgramType>,
    calls: Vec<ProgramCall>,
    bodies: Vec<ProgramBody>,
    value_transfers: Vec<ValueTransfer>,
    transformations: Vec<TypeTransformation>,
    state_reads: Vec<StateRead>,
    mutations: Vec<ProgramMutation>,
    fixed_point_iterations: usize,
}

/// Compiles one deterministic Rust-backed Program Semantic Model.
///
/// # Errors
///
/// Returns [`ProgramSemanticError`] for snapshot mutation, malformed supported
/// input, missing physical ownership, or disagreement with Implementation
/// Observation over a resolved cross-Module call.
pub fn compile_program_semantic_model(
    input: &ProgramSemanticInput,
) -> Result<ProgramSemanticModel, ProgramSemanticError> {
    let mut facts = rust::analyze(input)?;
    facts.packages.sort();
    facts.nominal_types.sort();
    facts.impls.sort();
    facts.symbols.sort();
    facts.types.sort();
    facts.calls.sort();
    facts.bodies.sort();
    facts.value_transfers.sort();
    facts.transformations.sort();
    facts.state_reads.sort();
    facts.mutations.sort();
    let topology = graph::derive_call_topology(&facts.symbols, &facts.calls);
    let module_boundaries = graph::derive_module_boundaries(&facts.symbols, &facts.calls);
    let missing = module_boundaries
        .iter()
        .filter_map(|boundary| {
            let boundary_edge = (
                boundary.source_module.clone(),
                boundary.target_module.clone(),
            );
            let callee_edge = (
                boundary.source_module.clone(),
                boundary.callee_module.clone(),
            );
            (!input
                .observed_module_dependencies()
                .contains(&boundary_edge)
                && !input.observed_module_dependencies().contains(&callee_edge))
            .then_some(format!(
                "{} -> {} (callee {}) via {}",
                boundary_edge.0, boundary_edge.1, callee_edge.1, boundary.call
            ))
        })
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(ProgramSemanticError::AnalyzerDisagreement(missing));
    }
    let analyzer_coherency = AnalyzerCoherency {
        status: "coherent".into(),
        checked_cross_module_calls: module_boundaries.len(),
        missing_observation_edges: Vec::new(),
    };
    let coverage = coverage(
        facts.source_files,
        &facts.packages,
        &facts.nominal_types,
        &facts.impls,
        &facts.symbols,
        &facts.calls,
        &facts.value_transfers,
        &facts.transformations,
        &facts.state_reads,
        &facts.mutations,
        &module_boundaries,
        &topology,
    );
    let resolution_summary = resolution_summary(&facts.calls, facts.fixed_point_iterations);
    Ok(ProgramSemanticModel {
        schema: PROGRAM_SEMANTIC_MODEL_SCHEMA.into(),
        schema_version: PROGRAM_SEMANTIC_MODEL_SCHEMA_VERSION,
        semantic_version: PROGRAM_SEMANTIC_MODEL_VERSION.into(),
        project_id: input.project_id().into(),
        source_identity: facts.source_identity,
        analyzers: vec![AnalyzerDescriptor::rust()],
        languages: vec!["rust".into()],
        packages: facts.packages,
        nominal_types: facts.nominal_types,
        impls: facts.impls,
        symbols: facts.symbols,
        types: facts.types,
        calls: facts.calls,
        bodies: facts.bodies,
        value_transfers: facts.value_transfers,
        transformations: facts.transformations,
        state_reads: facts.state_reads,
        mutations: facts.mutations,
        module_boundaries,
        call_topology: topology,
        resolution_summary,
        coverage,
        analyzer_coherency,
        unsupported_semantics: UNSUPPORTED_SEMANTICS
            .iter()
            .map(|value| (*value).into())
            .collect(),
        provenance: ProgramModelProvenance {
            identity_kind: "snapshot_bound_semantic_input_subset".into(),
            semantic_inputs: facts.source_inputs,
            ownership_authority: "ccg_physical_module_containment".into(),
            testing_authority: "ccg_verification_topology".into(),
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn coverage(
    source_files: usize,
    packages: &[ProgramPackage],
    nominal_types: &[NominalType],
    impls: &[ProgramImpl],
    symbols: &[ExecutableSymbol],
    calls: &[ProgramCall],
    transfers: &[ValueTransfer],
    transformations: &[TypeTransformation],
    state_reads: &[StateRead],
    mutations: &[ProgramMutation],
    module_boundaries: &[CrossModuleCall],
    topology: &CallTopology,
) -> ProgramCoverage {
    let count_calls = |state| calls.iter().filter(|call| call.state == state).count();
    ProgramCoverage {
        source_files,
        packages: packages.len(),
        executable_symbols: symbols.len(),
        nominal_types: nominal_types.len(),
        nominal_structs: nominal_types
            .iter()
            .filter(|item| item.kind == NominalTypeKind::Struct)
            .count(),
        nominal_enums: nominal_types
            .iter()
            .filter(|item| item.kind == NominalTypeKind::Enum)
            .count(),
        nominal_traits: nominal_types
            .iter()
            .filter(|item| item.kind == NominalTypeKind::Trait)
            .count(),
        nominal_type_aliases: nominal_types
            .iter()
            .filter(|item| item.kind == NominalTypeKind::TypeAlias)
            .count(),
        nominal_fields: nominal_types
            .iter()
            .map(|item| {
                item.fields.len()
                    + item
                        .variants
                        .iter()
                        .map(|variant| variant.fields.len())
                        .sum::<usize>()
            })
            .sum(),
        nominal_variants: nominal_types.iter().map(|item| item.variants.len()).sum(),
        impls: impls.len(),
        production_symbols: symbols
            .iter()
            .filter(|symbol| symbol.classification == SymbolClassification::Production)
            .count(),
        testing_symbols: symbols
            .iter()
            .filter(|symbol| symbol.classification == SymbolClassification::Testing)
            .count(),
        free_functions: count_symbols(symbols, ExecutableSymbolKind::FreeFunction),
        associated_functions: count_symbols(symbols, ExecutableSymbolKind::AssociatedFunction),
        inherent_methods: count_symbols(symbols, ExecutableSymbolKind::InherentMethod),
        trait_method_declarations: count_symbols(
            symbols,
            ExecutableSymbolKind::TraitMethodDeclaration,
        ),
        trait_method_implementations: count_symbols(
            symbols,
            ExecutableSymbolKind::TraitMethodImplementation,
        ),
        resolved_static_calls: count_calls(CallResolutionState::ResolvedStatic),
        external_calls: count_calls(CallResolutionState::External),
        dynamic_dispatch_calls: count_calls(CallResolutionState::DynamicDispatch),
        unresolved_calls: count_calls(CallResolutionState::Unresolved),
        unsupported_calls: count_calls(CallResolutionState::Unsupported),
        invalid_calls: count_calls(CallResolutionState::Invalid),
        cross_module_calls: module_boundaries.len(),
        cross_package_calls: topology.cross_package_calls.len(),
        recursive_components: topology
            .strongly_connected_components
            .iter()
            .filter(|component| component.recursive)
            .count(),
        value_transfers: transfers.len(),
        transformations: transformations.len(),
        state_reads: state_reads.len(),
        mutations: mutations.len(),
        resolved_mutations: mutations
            .iter()
            .filter(|item| item.resolution == PlaceResolutionState::ResolvedExact)
            .count(),
        uncertain_mutations: mutations
            .iter()
            .filter(|item| item.resolution != PlaceResolutionState::ResolvedExact)
            .count(),
    }
}

fn resolution_summary(calls: &[ProgramCall], fixed_point_iterations: usize) -> ResolutionSummary {
    let count = |state| calls.iter().filter(|call| call.state == state).count();
    let mut reasons = BTreeMap::new();
    for call in calls {
        if let Some(reason) = call.reason {
            let key = serde_json::to_value(reason)
                .expect("resolution reason serializes")
                .as_str()
                .expect("resolution reason is a string")
                .to_owned();
            *reasons.entry(key).or_insert(0) += 1;
        }
    }
    ResolutionSummary {
        resolved_static: count(CallResolutionState::ResolvedStatic),
        external: count(CallResolutionState::External),
        dynamic_dispatch: count(CallResolutionState::DynamicDispatch),
        unresolved: count(CallResolutionState::Unresolved),
        unsupported: count(CallResolutionState::Unsupported),
        invalid: count(CallResolutionState::Invalid),
        reasons,
        fixed_point_iterations,
    }
}

fn count_symbols(symbols: &[ExecutableSymbol], kind: ExecutableSymbolKind) -> usize {
    symbols.iter().filter(|symbol| symbol.kind == kind).count()
}

pub(crate) fn canonical_fact_id(prefix: &str, value: &impl Serialize) -> String {
    let bytes = serde_json::to_vec(value).expect("PSM fact identity material is serializable");
    format!("{prefix}:sha256:{:x}", Sha256::digest(bytes))
}

pub(crate) fn symbol_index(symbols: &[ExecutableSymbol]) -> BTreeMap<&str, &ExecutableSymbol> {
    symbols
        .iter()
        .map(|symbol| (symbol.id.as_str(), symbol))
        .collect()
}

/// Explains why PSM compilation could not establish coherent source facts.
#[derive(Debug)]
pub enum ProgramSemanticError {
    /// Snapshot-bound bytes do not match their stabilized identity.
    Observation(ImplementationObservationError),
    /// One Cargo manifest could not be interpreted.
    InvalidCargoManifest {
        /// Canonical repository-relative manifest path.
        path: String,
        /// Structural TOML parse error.
        source: toml::de::Error,
    },
    /// One Rust source artifact was not valid UTF-8.
    NonUtf8Rust(String),
    /// One Rust source artifact could not be structurally parsed.
    InvalidRustSource {
        /// Canonical repository-relative source path.
        path: String,
        /// Structural Rust parse error.
        source: syn::Error,
    },
    /// A governed source artifact had no unique physical Module owner.
    MissingSourceOwner(String),
    /// A Cargo target referenced a source artifact absent from the snapshot.
    MissingTargetSource(String),
    /// PSM cross-Module calls lacked the broader observation edge they imply.
    AnalyzerDisagreement(Vec<String>),
}

impl Display for ProgramSemanticError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observation(error) => write!(formatter, "snapshot-bound input failed: {error}"),
            Self::InvalidCargoManifest { path, source } => {
                write!(formatter, "Cargo manifest `{path}` is invalid: {source}")
            }
            Self::NonUtf8Rust(path) => write!(formatter, "Rust source `{path}` is not UTF-8"),
            Self::InvalidRustSource { path, source } => {
                write!(formatter, "Rust source `{path}` is invalid: {source}")
            }
            Self::MissingSourceOwner(path) => {
                write!(
                    formatter,
                    "Rust source `{path}` has no physical Module owner"
                )
            }
            Self::MissingTargetSource(path) => {
                write!(
                    formatter,
                    "Cargo target source `{path}` is absent from the snapshot"
                )
            }
            Self::AnalyzerDisagreement(edges) => write!(
                formatter,
                "PSM cross-Module call projection disagrees with Implementation Observation: {}",
                edges.join("; ")
            ),
        }
    }
}

impl Error for ProgramSemanticError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Observation(error) => Some(error),
            Self::InvalidCargoManifest { source, .. } => Some(source),
            Self::InvalidRustSource { source, .. } => Some(source),
            Self::NonUtf8Rust(_)
            | Self::MissingSourceOwner(_)
            | Self::MissingTargetSource(_)
            | Self::AnalyzerDisagreement(_) => None,
        }
    }
}

impl From<ImplementationObservationError> for ProgramSemanticError {
    fn from(error: ImplementationObservationError) -> Self {
        Self::Observation(error)
    }
}
