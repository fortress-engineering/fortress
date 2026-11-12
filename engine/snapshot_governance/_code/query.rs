//! Read-only inspection of immutable owner-produced governance results.
//!
//! Loading is explicit. Formatting and querying never invoke a semantic evaluator,
//! repair state, execute a project command, or grant authority to a proposal.

#[path = "query_authority.rs"]
mod authority;
#[path = "query_candidate.rs"]
mod candidate;
#[path = "query_explanation.rs"]
mod explanation;
#[path = "query_lifecycle.rs"]
mod lifecycle;
#[path = "query_load.rs"]
mod load;
#[path = "query_protocol.rs"]
mod protocol;
#[path = "query_transition.rs"]
mod transition;

pub(crate) use load::safe_read;
pub use load::{QueryLoadOptions, load_repository_query};
pub use protocol::*;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::audit::StateView;
use crate::contract_coherency::ContractCoherencyGraph;
use crate::reference_resolution::ComponentResolutionIndex;
use crate::standard::StandardBundle;

/// Existing immutable products admitted by the composition root.
/// None of these self-authenticate their producer or authorize a state change.
#[derive(Clone)]
pub struct QueryInput {
    /// Actual source observed by the caller; absent observations stay explicit.
    pub source_ref: String,
    /// Existing selected endpoint, including negative or partial results.
    pub state_view: Option<StateView>,
    /// Retained declaration/assessment pair when a historical generation omitted
    /// complete `StateView` proof metadata. Missing metadata stays explicitly absent.
    pub retained_application: Option<crate::application::ApplicationAssessment>,
    /// Existing canonical Module/relationship inventory.
    pub ccg: Option<ContractCoherencyGraph>,
    /// Existing reference-resolution relationships.
    pub references: Option<ComponentResolutionIndex>,
    /// Selected Standard supplying human rule meaning.
    pub standard: Option<StandardBundle>,
    /// Exact upstream normalized finding records, indexed by `finding_id`.
    pub findings: Vec<Value>,
    /// Exact upstream defeater records, indexed by id.
    pub defeaters: Vec<Value>,
    /// Original evidence graph records; no trust inferred from their strings.
    pub evidence_nodes: Vec<Value>,
    /// Upstream observed consumer/provider routes, separate from declarations.
    pub observed_routes: Vec<ObservedRoute>,
    /// Operational status prepared during explicit loading.
    pub availability: Value,
    /// Read-only diagnostic observations prepared during explicit loading.
    pub diagnostics: Value,
    /// Loading and semantic limitations, including unavailable upstream products.
    pub limitations: Vec<String>,
}

/// One upstream observed route, never permission by itself.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRoute {
    /// Actual consuming Module.
    pub consumer: String,
    /// Actual provider Module.
    pub provider: String,
    /// Producer-owned observation reference.
    pub evidence_ref: String,
}

impl QueryInput {
    /// Creates an explicitly unavailable loaded endpoint, useful for read-only hosts.
    #[must_use]
    pub fn empty(source_ref: String) -> Self {
        Self {
            source_ref,
            state_view: None,
            retained_application: None,
            ccg: None,
            references: None,
            standard: None,
            findings: Vec::new(),
            defeaters: Vec::new(),
            evidence_nodes: Vec::new(),
            observed_routes: Vec::new(),
            availability: json!({"evidence_state":"MISSING","local_materialization":"UNAVAILABLE","authenticity":"UNVERIFIED"}),
            diagnostics: json!({"configuration":"UNAVAILABLE","environment":"UNAVAILABLE","toolchain":"UNAVAILABLE","storage":"UNAVAILABLE"}),
            limitations: Vec::new(),
        }
    }
}

/// One admitted immutable input, with canonical ID and readable selector indexes.
pub struct QueryService {
    candidates: candidate::LoadedCandidates,
    flow_context: Option<(
        crate::program_semantics::ProgramSemanticModel,
        crate::information_flow::InformationFlowPolicy,
    )>,
    input: QueryInput,
    state_ref: String,
    names: BTreeMap<String, BTreeSet<String>>,
    records: Vec<QueryRecord>,
    evidence_edges: BTreeMap<String, Vec<String>>,
    index_bytes: usize,
    comparison_states: BTreeMap<String, crate::state_governance::ComparisonState>,
    comparison_identities: BTreeMap<String, (Option<String>, Option<String>)>,
    comparison_cache: transition::ComparisonCache,
}

impl QueryService {
    /// Admits a precomputed immutable authoring context. No analysis is initiated.
    ///
    /// # Errors
    /// Rejects oversized contexts or incompatible serialization.
    pub fn with_flow_context(
        mut self,
        source_ref: &str,
        psm: crate::program_semantics::ProgramSemanticModel,
        policy: crate::information_flow::InformationFlowPolicy,
    ) -> Result<Self, QueryError> {
        if source_ref != self.input.source_ref {
            return Err(QueryError::new(
                "STATE_MISMATCH",
                "flow authoring and query observations identify different source states",
            ));
        }
        if psm.symbols().len() > 100_000 || psm.calls().len() > 100_000 {
            return Err(QueryError::new(
                "RESOURCE_LIMIT",
                "flow context exceeds query admission",
            ));
        }
        self.state_ref = digest(&json!([
            self.state_ref,
            psm.digest()
                .map_err(|e| QueryError::new("INVALID_INPUT", e.to_string()))?,
            policy.digest()
        ]))?;
        self.flow_context = Some((psm, policy));
        Ok(self)
    }
    /// Validates the owner-produced endpoint and indexes it once without evaluation.
    ///
    /// # Errors
    /// Rejects invalid endpoints, inconsistent record identities and resource limits.
    pub fn new(input: QueryInput) -> Result<Self, QueryError> {
        if !crate::declaration::is_digest(&input.source_ref) {
            return Err(QueryError::new(
                "INVALID_INPUT",
                "actual source identity must be an exact digest",
            ));
        }
        if !input.availability.is_object()
            || !input.diagnostics.is_object()
            || (input.state_view.is_some() && input.retained_application.is_some())
        {
            return Err(QueryError::new(
                "INVALID_INPUT",
                "operational observations must be objects and only one application result can be selected",
            ));
        }
        if let Some(view) = &input.state_view {
            view.validate()
                .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
        }
        if let Some(app) = &input.retained_application {
            app.declaration
                .validate()
                .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
            app.assessment
                .validate()
                .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
            if app.declaration.binding != app.assessment.binding
                || app.assessment.declaration_digest
                    != app
                        .declaration
                        .digest()
                        .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?
            {
                return Err(QueryError::new(
                    "INVALID_INPUT",
                    "retained declaration and assessment do not bind the same input",
                ));
            }
        }
        let input_records = input
            .findings
            .len()
            .saturating_add(input.defeaters.len())
            .saturating_add(input.evidence_nodes.len())
            .saturating_add(input.observed_routes.len());
        if input_records > 100_000
            || input.ccg.as_ref().is_some_and(|graph| {
                graph
                    .modules()
                    .len()
                    .saturating_add(graph.direct_requirements().len())
                    .saturating_add(graph.relationships().len())
                    > 100_000
            })
        {
            return Err(QueryError::new(
                "RESOURCE_LIMIT",
                "supplied record count exceeds query admission",
            ));
        }
        let mut service = Self {
            flow_context: None,
            input,
            state_ref: String::new(),
            names: BTreeMap::new(),
            records: Vec::new(),
            evidence_edges: BTreeMap::new(),
            index_bytes: 0,
            comparison_states: BTreeMap::new(),
            candidates: BTreeMap::new(),
            comparison_identities: BTreeMap::new(),
            comparison_cache: Mutex::default(),
        };
        service.index()?;
        // Identity includes selected results, current authority, availability and diagnostics.
        // Timings are intentionally reported separately by callers, never inserted here.
        service.state_ref = digest(
            &json!({"version":1,"source":service.input.source_ref,"standard_digest":service.input.standard.as_ref().map(StandardBundle::digest),"state_view":service.input.state_view,"retained_application":service.input.retained_application,"records":service.records,"availability":service.input.availability,"limitations":service.input.limitations}),
        )?;
        Ok(service)
    }

    /// Returns the exact immutable query input identity used by continuations.
    #[must_use]
    pub fn state_ref(&self) -> &str {
        &self.state_ref
    }

    /// Returns the selected result's context, independently from actual freshness.
    #[must_use]
    pub fn context_ref(&self) -> Option<&str> {
        self.application()
            .map(|app| app.declaration.binding.context_ref.as_str())
    }

    fn application(&self) -> Option<&crate::application::ApplicationAssessment> {
        self.input
            .state_view
            .as_ref()
            .and_then(|view| view.application.as_ref())
            .or(self.input.retained_application.as_ref())
    }

    fn selected_source_ref(&self) -> Option<&str> {
        self.input
            .state_view
            .as_ref()
            .map(|view| view.source_ref.as_str())
            .or_else(|| {
                self.application()
                    .map(|app| app.declaration.binding.subject_ref.as_str())
            })
    }
    fn source_freshness(&self) -> SourceFreshness {
        self.selected_source_ref()
            .map_or(SourceFreshness::Missing, |source| {
                if source == self.input.source_ref {
                    SourceFreshness::Fresh
                } else {
                    SourceFreshness::Stale
                }
            })
    }

    /// Executes a typed read-only request; cancellation never changes the loaded input.
    #[must_use]
    pub fn execute(&self, request: &QueryRequest, cancelled: &AtomicBool) -> QueryResponse {
        let result = self.dispatch(request, cancelled);
        let mut response = self
            .response(Some(request.request_id.clone()), result)
            .for_protocol_version(request.protocol_version);
        if request.protocol_version >= 3
            && matches!(request.method.as_str(), "flow_author" | "behavior_author")
        {
            response.context_ref = self
                .flow_context
                .as_ref()
                .map(|(psm, _)| psm.program_context().digest());
        }
        response
    }

    /// Constructs a bounded structured boundary failure without a successful payload.
    #[must_use]
    pub fn failure(&self, request_id: Option<String>, error: QueryError) -> QueryResponse {
        self.response(request_id, Err(error))
    }

    /// Wraps adapter-owned lifecycle observations in the same canonical envelope.
    #[must_use]
    pub fn lifecycle_response(&self, request_id: String, result: Value) -> QueryResponse {
        self.response(Some(request_id), Ok(QueryPayload::Protocol(result)))
    }

    fn response(
        &self,
        request_id: Option<String>,
        result: Result<QueryPayload, QueryError>,
    ) -> QueryResponse {
        let (result, error) = match result {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error)),
        };
        let operational_state = error
            .as_ref()
            .map_or("COMPLETED", |error| {
                if error.code == "CANCELLED" {
                    "CANCELLED"
                } else {
                    "FAILED"
                }
            })
            .into();
        let mut response = QueryResponse {schema:"urn:fortress:protocol:v1:query-response".into(),protocol_version:QUERY_PROTOCOL_VERSION,request_id,state_ref:self.state_ref.clone(),actual_source_ref:self.input.source_ref.clone(),selected_source_ref:self.selected_source_ref().map(str::to_owned),source_freshness:self.source_freshness(),context_ref:self.context_ref().map(str::to_owned),result,error,limitations:vec!["Read-only projection of supplied immutable results; no fresh semantic analysis or repair was performed.".into(),"Digest integrity does not establish producer authenticity. Suggested edits remain proposals.".into()],operational_state};
        response.limitations.extend(self.input.limitations.clone());
        if response.source_freshness == SourceFreshness::Stale {
            response.limitations.push("Selected evidence is historical and does not establish current repository conformance. Authored current policy and selected evaluations retain separate provenance.".into());
        }
        if let Err(error) = response.to_canonical_bytes() {
            response.result = None;
            response.error = Some(error);
            response.operational_state = "FAILED".into();
        }
        response
    }

    fn dispatch(
        &self,
        request: &QueryRequest,
        cancelled: &AtomicBool,
    ) -> Result<QueryPayload, QueryError> {
        if ![QUERY_PROTOCOL_VERSION, 2, 3, 4, 5].contains(&request.protocol_version) {
            return Err(QueryError::new(
                "UNSUPPORTED_VERSION",
                "only protocol_version 1, 2, 3, 4 and 5 are supported",
            ));
        }
        check_cancelled(cancelled)?;
        let flow_context = if matches!(request.method.as_str(), "flow_author" | "behavior_author") {
            self.flow_context
                .as_ref()
                .map(|(psm, _)| psm.program_context().digest())
        } else {
            None
        };
        let context_ref = if matches!(request.method.as_str(), "flow_author" | "behavior_author") {
            flow_context.as_deref()
        } else {
            self.context_ref()
        };
        if request
            .state_ref
            .as_deref()
            .is_some_and(|state| state != self.state_ref)
            || request
                .context_ref
                .as_deref()
                .is_some_and(|context| Some(context) != context_ref)
        {
            return Err(QueryError::new(
                "STATE_MISMATCH",
                "request does not identify this loaded state/context",
            ));
        }
        let result = match request.operation()? {
            QueryOperation::Candidate(parameters) => {
                QueryPayload::Explanation(self.inspect_candidate(&parameters, cancelled)?)
            }
            QueryOperation::BehaviorAuthor(parameters) => {
                let (psm,_)=self.flow_context.as_ref().ok_or_else(||QueryError::new("UNAVAILABLE","No immutable authoring context was explicitly admitted; formatting does not initiate analysis."))?;
                QueryPayload::Authoring(
                    crate::behavioral_realization::preview_behavior_contract(psm, &parameters)
                        .map_err(|e| QueryError::new("INVALID_PROPOSAL", e.to_string()))?,
                )
            }
            QueryOperation::FlowAuthor(parameters) => {
                let (psm,policy) = self.flow_context.as_ref().ok_or_else(||QueryError::new("UNAVAILABLE","No immutable flow authoring context was explicitly admitted. Query formatting never starts analysis."))?;
                QueryPayload::Authoring(
                    crate::information_flow::preview_operation_policy(psm, policy, &parameters)
                        .map_err(|e| QueryError::new("INVALID_PROPOSAL", e.to_string()))?,
                )
            }
            QueryOperation::Transition(parameters) => {
                QueryPayload::Transition(self.compare_transition(&parameters, cancelled)?)
            }
            QueryOperation::Status(_) => QueryPayload::Status(self.status()),
            QueryOperation::Doctor(_) => QueryPayload::Doctor(self.input.diagnostics.clone()),
            QueryOperation::Protocol(_) => QueryPayload::Protocol(
                json!({"methods":METHODS.iter().filter(|m| (request.protocol_version >= 2 || **m != "transition") && (request.protocol_version >= 3 || **m != "flow_author") && (request.protocol_version >= 4 || **m != "behavior_author") && (request.protocol_version >= 5 || **m != "candidate")).collect::<Vec<_>>(),"protocol_versions":[1,2,3,4,5],"flow_authoring_context":self.flow_context.as_ref().map(|(psm,_)|json!({"context_ref":psm.program_context().digest(),"psm_source_ref":psm.source_identity()})),"comparison_states":self.comparison_state_inventory(),"max_request_bytes":MAX_REQUEST_BYTES,"max_response_bytes":MAX_RESPONSE_BYTES,"max_page_size":MAX_PAGE_SIZE,"framing":"one strict UTF-8 JSON request per LF-delimited line","mutation":false}),
            ),
            QueryOperation::Query(parameters) => {
                QueryPayload::Page(self.select(&parameters, cancelled)?)
            }
            QueryOperation::Explain(parameters) => {
                QueryPayload::Explanation(self.explain(&parameters, cancelled)?)
            }
            QueryOperation::Author(parameters) => {
                QueryPayload::Authoring(self.author(&parameters)?)
            }
            QueryOperation::Cancel(_) | QueryOperation::Progress(_) => {
                return Err(QueryError::new(
                    "ADAPTER_REQUIRED",
                    "lifecycle requests require the adapter active-request registry",
                ));
            }
        };
        check_cancelled(cancelled)?;
        Ok(result)
    }

    fn status(&self) -> Value {
        let mut result = self.input.availability.clone();
        let app = self.application();
        let selected_source = self
            .input
            .state_view
            .as_ref()
            .map(|view| view.source_ref.as_str())
            .or_else(|| app.map(|app| app.declaration.binding.subject_ref.as_str()));
        result["actual_source_ref"] = json!(self.input.source_ref);
        result["actual_authority"] = json!({"configuration":self.input.diagnostics.get("configuration"),"detail":self.input.diagnostics.get("configuration_detail").or_else(||self.input.diagnostics.get("detail")),"input_validity":self.input.diagnostics.get("input_validity")});
        result["selected_source_ref"] = json!(selected_source);
        result["source_freshness"] =
            json!(
                selected_source.map_or("MISSING", |source| if source == self.input.source_ref {
                    "FRESH"
                } else {
                    "STALE"
                })
            );
        result["current_repository_proven"] = json!(false);
        result["freshness_limit"] = json!(
            "Fresh means exact source bytes matched at explicit loading; host/toolchain context and authenticated provenance are separate. A selected historical result proves only its recorded subject."
        );
        result["raw_conformance"] = json!(app.map(|app| &app.declaration.dimensions));
        result["progressive_enforcement"] = json!(app.map(|app| &app.declaration.residue_summary));
        result["assurance_assessment"] = json!(app.map(|app| &app.assessment));
        result["profiles"] =
            json!(app.map(|app| &app.declaration.required_dimension_manifest.profiles));
        result["standard"] = json!(self.input.standard.as_ref().map(|standard|json!({"id":standard.id(),"edition":standard.edition(),"digest":standard.digest()})));
        let mut findings = self
            .records
            .iter()
            .filter(|record| record.kind == "finding")
            .map(|record| record.id.as_str())
            .collect::<BTreeSet<_>>();
        if let Some(app) = app {
            findings.extend(
                app.declaration
                    .claims
                    .iter()
                    .flat_map(|claim| claim.findings.iter().map(String::as_str)),
            );
        }
        result["finding_count"] = json!(findings.len());
        result["coverage"] = json!(app.map(|app|app.declaration.claims.iter().filter_map(|claim|claim.semantic_claim.as_ref().map(|detail|json!({"claim_id":claim.id,"module":detail.module_id,"scope_selector":detail.scope_selector,"governed_source_files":detail.governed_source_files,"analysed_source_files":detail.analysed_source_files,"production_observations":detail.production_observations.len(),"test_observations":detail.test_observations.len(),"unknown_observations":detail.unknown_observations.len()}))).collect::<Vec<_>>()));
        result["ccg_unsupported_semantics"] = json!(
            self.input
                .ccg
                .as_ref()
                .map(ContractCoherencyGraph::unsupported_semantics)
        );
        result["unsupported_unknown"] = json!(app.map(|app|app.declaration.claims.iter().filter(|claim| claim.truth == crate::declaration::DeclarationTruth::NotEvaluable).map(|claim|json!({"id":claim.id,"reasons":claim.reason_codes,"defeaters":claim.defeater_refs})).collect::<Vec<_>>()));
        result
    }

    fn add_record(
        &mut self,
        kind: &str,
        id: impl Into<String>,
        scope: impl Into<String>,
        value: Value,
    ) -> Result<(), QueryError> {
        if self.records.len() >= 100_000 {
            return Err(QueryError::new(
                "RESOURCE_LIMIT",
                "query index record limit reached",
            ));
        }
        let bytes = serde_json::to_vec(&value)
            .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?
            .len();
        self.index_bytes = self
            .index_bytes
            .checked_add(bytes)
            .filter(|total| *total <= 64 * 1024 * 1024)
            .ok_or_else(|| QueryError::new("RESOURCE_LIMIT", "query index byte limit reached"))?;
        self.records.push(QueryRecord {
            id: id.into(),
            kind: kind.into(),
            scope_ref: scope.into(),
            value,
        });
        Ok(())
    }

    fn index(&mut self) -> Result<(), QueryError> {
        self.index_authority()?;
        self.index_application()?;
        for (kind, values) in [
            ("finding", self.input.findings.clone()),
            ("defeater", self.input.defeaters.clone()),
            ("evidence_node", self.input.evidence_nodes.clone()),
        ] {
            for value in values {
                let id = value
                    .get("finding_id")
                    .or_else(|| value.get("id"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        QueryError::new("INVALID_INPUT", "upstream record lacks an identity")
                    })?
                    .to_owned();
                if kind == "evidence_node" {
                    let mut edges = BTreeSet::new();
                    for field in [
                        "inputs",
                        "evidence_refs",
                        "children",
                        "supporting_refs",
                        "counterevidence_refs",
                    ] {
                        if let Some(values) = value[field].as_array() {
                            edges
                                .extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
                        }
                    }
                    self.evidence_edges
                        .insert(id.clone(), edges.into_iter().collect());
                }
                self.add_record(kind, id, "upstream", value)?;
            }
        }
        for route in self.input.observed_routes.clone() {
            self.add_record("route",format!("observed:{}:{}:{}",route.consumer,route.provider,route.evidence_ref),route.consumer.clone(),json!({"consumer":route.consumer,"provider":route.provider,"evidence_ref":route.evidence_ref,"classification":"OBSERVED","permission":"UNESTABLISHED"}))?;
        }
        self.index_unresolved_references()?;
        self.records.sort_by(|left, right| {
            (&left.kind, &left.id, &left.scope_ref).cmp(&(&right.kind, &right.id, &right.scope_ref))
        });
        if self.records.windows(2).any(|pair| {
            (&pair[0].kind, &pair[0].id, &pair[0].scope_ref)
                == (&pair[1].kind, &pair[1].id, &pair[1].scope_ref)
        }) {
            return Err(QueryError::new(
                "INVALID_INPUT",
                "duplicate indexed record identity",
            ));
        }
        let bytes = crate::declaration::canonical(&self.records)
            .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?;
        if bytes.len() > 64 * 1024 * 1024 {
            return Err(QueryError::new(
                "RESOURCE_LIMIT",
                "query index byte limit reached",
            ));
        }
        Ok(())
    }

    fn index_unresolved_references(&mut self) -> Result<(), QueryError> {
        let known = self
            .records
            .iter()
            .map(|record| record.id.clone())
            .chain(self.evidence_edges.keys().cloned())
            .collect::<BTreeSet<_>>();
        let mut cited = self
            .evidence_edges
            .values()
            .flatten()
            .cloned()
            .collect::<BTreeSet<_>>();
        if let Some(app) = self.application() {
            for claim in &app.declaration.claims {
                cited.extend(
                    claim
                        .proof_refs
                        .iter()
                        .chain(&claim.defeater_refs)
                        .chain(&claim.findings)
                        .cloned(),
                );
            }
        }
        for id in cited.difference(&known) {
            self.add_record("unresolved_reference",id,"UNAVAILABLE",json!({"reference":id,"availability":"UNAVAILABLE","meaning":"Referenced upstream evidence was not supplied; no truth or permission is inferred from its absence."}))?;
        }
        Ok(())
    }

    fn index_authority(&mut self) -> Result<(), QueryError> {
        let Some(graph) = self.input.ccg.clone() else {
            return Ok(());
        };
        for (id, module) in graph.modules() {
            let mut names = vec![module.contract().display_name()];
            let mut parent = module.parent_id();
            while let Some(parent_id) = parent {
                let ancestor = graph
                    .modules()
                    .get(parent_id)
                    .ok_or_else(|| QueryError::new("INVALID_INPUT", "Module parent is missing"))?;
                names.push(ancestor.contract().display_name());
                parent = ancestor.parent_id();
                if names.len() > graph.modules().len() {
                    return Err(QueryError::new("INVALID_INPUT", "cyclic Module parentage"));
                }
            }
            names.reverse();
            let qualified = names.join("::");
            for name in [
                id.as_str(),
                module.contract().display_name(),
                qualified.as_str(),
                module.path(),
            ] {
                self.names
                    .entry(name.into())
                    .or_default()
                    .insert(id.clone());
            }
            self.add_record("module",id,id,json!({"id":id,"display_name":module.contract().display_name(),"qualified_name":qualified,"path":module.path(),"contract_path":module.contract_path(),"contract_digest":module.digest(),"parent":module.parent_id()}))?;
            self.add_record("policy",id,id,json!({"authored_policy":module.contract().semantic_policy(),"contract_path":module.contract_path(),"contract_digest":module.digest(),"limitations":"Authored intent; upstream evaluated claim records describe effective policy. Absence of policy is not permission."}))?;
        }
        for (index, edge) in graph.direct_requirements().iter().enumerate() {
            self.add_record("route",format!("declared:{index}"),edge.consumer(),json!({"consumer":edge.consumer(),"provider":edge.provider(),"capability":edge.capability(),"version_requirement":edge.version_requirement(),"classification":"DECLARED_PERMITTED","provenance":{"path":edge.provenance().contract_path(),"pointer":edge.provenance().pointer()},"limitations":"Permission is the exact declared capability requirement; a transitive path grants no extra permission."}))?;
        }
        for (index, edge) in graph.relationships().iter().enumerate() {
            self.add_record("relationship",format!("relationship:{index}"),edge.source(),json!({"source":edge.source(),"target":edge.target(),"kind":edge.kind(),"subjects":edge.subjects(),"provenance":{"path":edge.provenance().contract_path(),"pointer":edge.provenance().pointer()}}))?;
        }
        if let Some(index) = self.input.references.clone() {
            for (number, fact) in index.references().iter().enumerate() {
                self.add_record(
                    "reference",
                    format!("reference:{number}"),
                    fact.source_module(),
                    serde_json::to_value(fact)
                        .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))?,
                )?;
            }
        }
        Ok(())
    }

    fn resolve(&self, selector: &str) -> Result<String, QueryError> {
        match self.names.get(selector) {
            Some(candidates) if candidates.len() == 1 => Ok(candidates
                .iter()
                .next()
                .expect("one indexed candidate")
                .clone()),
            Some(candidates) => Err(QueryError {
                code: "AMBIGUOUS_SELECTOR".into(),
                message:
                    "selector has multiple candidates; use a canonical ID or full qualified name"
                        .into(),
                candidates: candidates.iter().cloned().collect(),
            }),
            None => Err(QueryError::new(
                "NOT_FOUND",
                "no declared Module matches this selector",
            )),
        }
    }

    fn select(
        &self,
        parameters: &SelectParameters,
        cancelled: &AtomicBool,
    ) -> Result<QueryPage, QueryError> {
        let module = parameters
            .selector
            .as_deref()
            .map(|name| self.resolve(name))
            .transpose()?;
        if !matches!(parameters.kind, QueryKind::Modules) && module.is_none() {
            return Err(QueryError::new(
                "INVALID_PARAMETERS",
                "this query requires a Module selector",
            ));
        }
        let graph = self.input.ccg.as_ref().ok_or_else(|| {
            QueryError::new("UNAVAILABLE", "canonical Module inventory is not loaded")
        })?;
        let target = parameters
            .target
            .as_deref()
            .map(|target| {
                if graph.capabilities().contains_key(target) {
                    Ok(target.to_owned())
                } else {
                    self.resolve(target)
                }
            })
            .transpose()?;
        let mut selected = Vec::new();
        for (index, record) in self.records.iter().enumerate() {
            check_cancelled(cancelled)?;
            let matches = match parameters.kind {
                QueryKind::Modules => {
                    record.kind == "module"
                        && module.as_ref().is_none_or(|module| record.id == *module)
                }
                QueryKind::Policy => {
                    (record.kind == "policy" || record.kind == "claim")
                        && module
                            .as_ref()
                            .is_some_and(|module| record.scope_ref == *module)
                }
                QueryKind::Dependents => {
                    record.kind == "route"
                        && record.value["classification"] == "DECLARED_PERMITTED"
                        && module.as_deref() == record.value["provider"].as_str()
                }
                QueryKind::Routes => {
                    record.kind == "route"
                        && module.as_deref() == record.value["consumer"].as_str()
                        && target.as_ref().is_none_or(|target| {
                            record.value["provider"].as_str() == Some(target)
                                || record.value["capability"].as_str() == Some(target)
                        })
                }
                QueryKind::Relationships => {
                    record.kind == "relationship"
                        && module.as_deref() == record.value["source"].as_str()
                }
                QueryKind::References => {
                    record.kind == "reference"
                        && module
                            .as_ref()
                            .is_some_and(|module| record.scope_ref == *module)
                }
            };
            if matches {
                selected.push(index);
            }
        }
        if matches!(parameters.kind, QueryKind::References) && self.input.references.is_none() {
            return Err(QueryError::new(
                "UNAVAILABLE",
                "reference-resolution product is not loaded",
            ));
        }
        self.page(
            &selected,
            &parameters.page,
            &digest(&json!({"query":parameters.kind,"module":module,"target":target}))?,
            cancelled,
        )
    }

    fn page(
        &self,
        selected: &[usize],
        parameters: &PageParameters,
        query_key: &str,
        cancelled: &AtomicBool,
    ) -> Result<QueryPage, QueryError> {
        if !(1..=MAX_PAGE_SIZE).contains(&parameters.limit) {
            return Err(QueryError::new(
                "RESOURCE_LIMIT",
                "page limit must be between 1 and 200",
            ));
        }
        let signature = digest(&json!([self.state_ref, query_key]))?;
        let offset = if let Some(cursor) = &parameters.cursor {
            let (prefix, position) = cursor
                .rsplit_once(':')
                .ok_or_else(|| QueryError::new("INVALID_CURSOR", "malformed continuation"))?;
            if prefix != signature {
                return Err(QueryError::new(
                    "INVALID_CURSOR",
                    "continuation belongs to another state or query",
                ));
            }
            position
                .parse::<usize>()
                .map_err(|_| QueryError::new("INVALID_CURSOR", "invalid continuation offset"))?
        } else {
            0
        };
        if offset > selected.len() {
            return Err(QueryError::new(
                "INVALID_CURSOR",
                "continuation exceeds result count",
            ));
        }
        let end = offset.saturating_add(parameters.limit).min(selected.len());
        let mut records = Vec::with_capacity(end - offset);
        for index in &selected[offset..end] {
            check_cancelled(cancelled)?;
            records.push(self.records[*index].clone());
        }
        Ok(QueryPage {
            total: selected.len(),
            offset,
            records,
            next_cursor: (end < selected.len()).then(|| format!("{signature}:{end}")),
        })
    }
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<(), QueryError> {
    if cancelled.load(Ordering::Acquire) {
        Err(QueryError::new(
            "CANCELLED",
            "request cancelled; loaded state is unchanged",
        ))
    } else {
        Ok(())
    }
}

fn digest(value: &Value) -> Result<String, QueryError> {
    crate::declaration::canonical(value)
        .map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)))
        .map_err(|error| QueryError::new("INVALID_INPUT", error.to_string()))
}
