//! Dedicated lifetime for coordinator-local parser handles and owner preparations.
//!
//! Finished immutable models cross the channel. Syntax and parser source maps
//! remain on one thread and disappear when that thread is joined. Preparation
//! publication is a separate transaction from finished model production.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};

use crate::audit::{
    AuditError, ResidentEvaluation, ResidentPreparation, ResidentWork, prepare_resident_view,
};
use crate::certification::RustSuiteExecution;
use crate::observation::{SourceView, input_retention};
use crate::session::{SessionError, SessionErrorKind};

const MAX_PARSER_ADMISSION: usize = 1024 * 1024 * 1024;
const PARSER_ALLOCATION_MULTIPLIER: usize = 64;
const MAX_COLD_PARSER_DEMANDS: usize = 8;
const COLD_PARSER_DEMAND_METADATA_BYTES: usize = 4096;

/// Operational worker bounds, excluded from every semantic identity.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WorkerLimits {
    pub(crate) parser_bytes: usize,
    pub(crate) preparation_bytes: usize,
    pub(crate) preparation_units: usize,
}

enum PendingPreparation {
    Empty,
    Ready(Box<ResidentPreparation>),
    Evicted,
}

/// Completed models and actual local-retention measurements for one request.
pub(crate) struct WorkerEvaluation {
    pub(crate) evaluation: ResidentEvaluation,
    pub(crate) work: ResidentWork,
    pub(crate) preparation_bytes: usize,
    pub(crate) preparation_units: usize,
    pub(crate) pending_program_preparation: bool,
    pub(crate) retained_preparation_bytes: usize,
    pub(crate) complete_prior_owner_preparation: bool,
    pub(crate) preparation_bytes_before_eviction: usize,
    pub(crate) preparation_units_before_eviction: usize,
    pub(crate) preparation_bytes_by_owner: [usize; 3],
    pub(crate) parser_bytes: usize,
    pub(crate) parser_resident_charge: usize,
    pub(crate) parser_input_bytes: usize,
    pub(crate) parser_tokenizations: usize,
    pub(crate) input_bytes_tokenized: usize,
    pub(crate) tokenizations: usize,
    pub(crate) admission_bytes_added: usize,
    pub(crate) discarded_parser_bytes: usize,
    pub(crate) discarded_input_bytes: usize,
    pub(crate) discarded_tokenizations: usize,
    pub(crate) parser_rotated: bool,
    pub(crate) reasons: Vec<String>,
}

struct EvaluationReply {
    result: Result<WorkerEvaluation, SessionError>,
    usage: input_retention::InputRetentionState,
    exhausted: bool,
}

enum Request {
    Evaluate {
        view: SourceView,
        reuse: bool,
        reply: SyncSender<EvaluationReply>,
    },
    Commit {
        retain: bool,
        reply: SyncSender<Result<(), SessionError>>,
    },
    Discard(SyncSender<Result<(), SessionError>>),
    Evict(SyncSender<Result<(), SessionError>>),
    Stop,
}

/// Owns one dedicated parser epoch without moving any parser handle across threads.
pub(crate) struct ResidentWorker {
    root: PathBuf,
    suite: Option<RustSuiteExecution>,
    limits: WorkerLimits,
    sender: Option<SyncSender<Request>>,
    thread: Option<JoinHandle<()>>,
    usage: input_retention::InputRetentionState,
    retained_bytes: usize,
    pending_bytes: Option<usize>,
    retained_program: bool,
    pending_program: Option<bool>,
    // Only successful cold-program requests train this bounded operational hint.
    // Source identity and all fixed worker context must still match. It never
    // supplies semantic results or replaces parser admission and cold evaluation.
    cold_parser_demands: VecDeque<(String, usize)>,
}

impl ResidentWorker {
    pub(crate) fn start(
        root: &Path,
        suite: Option<RustSuiteExecution>,
        limits: WorkerLimits,
    ) -> Result<Self, SessionError> {
        if limits.parser_bytes == 0
            || limits.parser_bytes > MAX_PARSER_ADMISSION
            || limits
                .parser_bytes
                .checked_mul(PARSER_ALLOCATION_MULTIPLIER)
                .is_none()
        {
            return Err(SessionError::new(
                SessionErrorKind::InvalidInput,
                "parser admission must be nonzero and at most one GiB",
            ));
        }
        let mut worker = Self {
            root: root.into(),
            suite,
            limits,
            sender: None,
            thread: None,
            usage: input_retention::InputRetentionState::default(),
            retained_bytes: 0,
            pending_bytes: None,
            retained_program: false,
            pending_program: None,
            cold_parser_demands: VecDeque::with_capacity(MAX_COLD_PARSER_DEMANDS),
        };
        worker.spawn_epoch()?;
        Ok(worker)
    }

    /// The coordinator reserves parser and bounded admission-hint metadata until join.
    pub(crate) fn maximum_parser_charge(&self) -> usize {
        self.limits.parser_bytes * PARSER_ALLOCATION_MULTIPLIER + COLD_PARSER_DEMAND_METADATA_BYTES
    }

    /// Returns the acknowledged charge of preparation still retained by the epoch.
    /// Pending preparation is charged separately until commit acknowledgement.
    pub(crate) const fn retained_preparation_bytes(&self) -> usize {
        self.retained_bytes
    }

    fn spawn_epoch(&mut self) -> Result<(), SessionError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let root = self.root.clone();
        let suite = self.suite.clone();
        let limits = self.limits;
        let thread = thread::Builder::new()
            .name("fortress-resident-parser".into())
            .spawn(move || run_epoch(&root, suite.as_ref(), limits, &receiver))
            .map_err(|error| worker_error(error.to_string()))?;
        self.sender = Some(sender);
        self.thread = Some(thread);
        self.usage = input_retention::InputRetentionState::default();
        Ok(())
    }

    fn send(&mut self, request: Request) -> Result<(), SessionError> {
        let result = self
            .sender
            .as_ref()
            .ok_or_else(|| worker_error("resident parser worker is closed"))
            .and_then(|sender| {
                sender.send(request).map_err(|_| {
                    worker_error("resident parser worker stopped before completing the request")
                })
            });
        result.map_err(|error| self.failed_rpc(error))
    }

    fn failed_rpc(&mut self, error: SessionError) -> SessionError {
        // A failed transport cannot acknowledge which preparations remain.
        // Joining the epoch establishes their release before clearing charges.
        match self.close() {
            Ok(()) => error,
            Err(join_error) => worker_error(format!("{error}; {join_error}")),
        }
    }

    fn evaluate_once(
        &mut self,
        view: SourceView,
        reuse: bool,
    ) -> Result<EvaluationReply, SessionError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.send(Request::Evaluate { view, reuse, reply })?;
        let reply = response
            .recv()
            .map_err(|_| worker_error("resident parser worker did not return a completed response"))
            .map_err(|error| self.failed_rpc(error))?;
        self.usage = reply.usage;
        if let Ok(evaluation) = &reply.result {
            self.retained_bytes = evaluation.retained_preparation_bytes;
            self.pending_bytes = Some(evaluation.preparation_bytes);
            self.pending_program = Some(evaluation.pending_program_preparation);
        } else {
            self.pending_bytes = None;
            self.pending_program = None;
        }
        Ok(reply)
    }

    pub(crate) fn evaluate(
        &mut self,
        view: SourceView,
        reuse: bool,
    ) -> Result<WorkerEvaluation, SessionError> {
        let initial = self.usage;
        let digest = view.digest().to_owned();
        let cold_program = !reuse || !self.retained_program;
        let predicted_rotation = cold_program
            && initial.input_count > 0
            && self.cold_parser_demands.iter().any(|(identity, demand)| {
                identity == &digest
                    && initial
                        .admission_bytes
                        .checked_add(*demand)
                        .is_none_or(|total| total > self.limits.parser_bytes)
            });
        let mut rotated = false;
        let mut discarded_bytes = 0;
        let mut discarded_input_bytes = 0;
        let mut discarded_tokenizations = 0;
        // An earlier failed request can exhaust an epoch. Its handles must die
        // with that thread before a fresh evaluation can be attempted.
        if initial.exhausted || predicted_rotation {
            self.rotate()?;
            rotated = true;
        }
        let mut rebuilt_program = cold_program || rotated;
        let mut before = self.usage;
        let mut reply = self.evaluate_once(view.clone(), reuse && !rotated)?;
        if reply.exhausted && before.input_count > 0 {
            discarded_bytes = reply.usage.admission_bytes - before.admission_bytes;
            discarded_input_bytes = reply.usage.input_bytes - before.input_bytes;
            discarded_tokenizations = reply.usage.input_count - before.input_count;
            self.rotate()?;
            rotated = true;
            rebuilt_program = true;
            before = self.usage;
            reply = self.evaluate_once(view, false)?;
        }
        let mut evaluation = reply.result?;
        if rebuilt_program {
            self.remember_cold_demand(digest, reply.usage.admission_bytes - before.admission_bytes);
        }
        evaluation.input_bytes_tokenized =
            reply.usage.input_bytes - before.input_bytes + discarded_input_bytes;
        evaluation.tokenizations =
            reply.usage.input_count - before.input_count + discarded_tokenizations;
        evaluation.admission_bytes_added =
            reply.usage.admission_bytes - before.admission_bytes + discarded_bytes;
        evaluation.discarded_parser_bytes = discarded_bytes;
        evaluation.discarded_input_bytes = discarded_input_bytes;
        evaluation.discarded_tokenizations = discarded_tokenizations;
        evaluation.parser_rotated = rotated;
        if rotated {
            evaluation
                .reasons
                .push("resident_parser_epoch_rotated_to_cold_evaluation".into());
        }
        if predicted_rotation {
            evaluation
                .reasons
                .push("resident_parser_epoch_rotated_before_known_cold_admission".into());
        }
        Ok(evaluation)
    }

    fn remember_cold_demand(&mut self, digest: String, bytes: usize) {
        self.cold_parser_demands
            .retain(|(identity, _)| identity != &digest);
        if self.cold_parser_demands.len() == MAX_COLD_PARSER_DEMANDS {
            self.cold_parser_demands.pop_front();
        }
        self.cold_parser_demands.push_back((digest, bytes));
    }

    /// Promotes pending preparation only after the coordinator's actual commit.
    pub(crate) fn commit(&mut self, retain: bool) -> Result<(), SessionError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.send(Request::Commit { retain, reply })?;
        let result = response
            .recv()
            .map_err(|_| worker_error("resident preparation commit was not acknowledged"))
            .map_err(|error| self.failed_rpc(error))?;
        if result.is_ok() {
            self.retained_bytes = if retain {
                self.pending_bytes.unwrap_or(0)
            } else {
                0
            };
            self.pending_bytes = None;
            let program = self.pending_program.take().unwrap_or(false);
            self.retained_program = retain && program;
        }
        result
    }

    /// Drops hypothetical or failed pending preparation while preserving prior units.
    pub(crate) fn discard(&mut self) -> Result<(), SessionError> {
        self.acknowledge(Request::Discard)?;
        self.pending_bytes = None;
        self.pending_program = None;
        Ok(())
    }

    /// Evicts owner preparations; parser input charge remains until the epoch ends.
    pub(crate) fn evict(&mut self) -> Result<(), SessionError> {
        self.acknowledge(Request::Evict)?;
        self.retained_bytes = 0;
        self.pending_bytes = None;
        self.retained_program = false;
        self.pending_program = None;
        Ok(())
    }

    fn acknowledge(
        &mut self,
        request: fn(SyncSender<Result<(), SessionError>>) -> Request,
    ) -> Result<(), SessionError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.send(request(reply))?;
        response
            .recv()
            .map_err(|_| worker_error("resident preparation update was not acknowledged"))
            .map_err(|error| self.failed_rpc(error))?
    }

    fn rotate(&mut self) -> Result<(), SessionError> {
        self.close()?;
        self.spawn_epoch()
    }

    /// Stops and joins the worker before its retained allocation permit is released.
    pub(crate) fn close(&mut self) -> Result<(), SessionError> {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(Request::Stop);
        }
        let result = if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| worker_error("resident parser worker panicked"))
        } else {
            Ok(())
        };
        // Even a panic acknowledgement proves this epoch has ended. A failed
        // spawn following rotation likewise cannot revive its preparations.
        self.retained_bytes = 0;
        self.pending_bytes = None;
        self.retained_program = false;
        self.pending_program = None;
        result
    }
}

impl Drop for ResidentWorker {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn worker_error(detail: impl Into<String>) -> SessionError {
    SessionError::new(SessionErrorKind::Evaluation, detail)
}

fn parser_limit() -> SessionError {
    SessionError::new(
        SessionErrorKind::ResourceLimit,
        "retained parser input admission limit exceeded",
    )
}

fn evaluation_error(error: &AuditError) -> SessionError {
    let kind = if matches!(error, AuditError::ResidentSourceLimit { .. }) {
        SessionErrorKind::ResourceLimit
    } else {
        SessionErrorKind::Evaluation
    };
    SessionError::new(kind, error.to_string())
}

fn run_epoch(
    root: &Path,
    suite: Option<&RustSuiteExecution>,
    limits: WorkerLimits,
    requests: &Receiver<Request>,
) {
    // This thread is new: no source-map entries or syntax handles exist yet.
    if input_retention::begin(limits.parser_bytes).is_err() {
        return;
    }
    let mut retained: Option<ResidentPreparation> = None;
    let mut pending = PendingPreparation::Empty;
    while let Ok(request) = requests.recv() {
        match request {
            Request::Evaluate { view, reuse, reply } => {
                let result = prepare_evaluation(
                    root,
                    suite,
                    limits,
                    view,
                    reuse,
                    retained.as_ref(),
                    &mut pending,
                );
                let _ = reply.send(result);
            }
            Request::Commit { retain, reply } => {
                let result = match std::mem::replace(&mut pending, PendingPreparation::Empty) {
                    PendingPreparation::Ready(preparation) => {
                        retained = if retain { Some(*preparation) } else { None };
                        Ok(())
                    }
                    PendingPreparation::Evicted => {
                        retained = None;
                        Ok(())
                    }
                    PendingPreparation::Empty => {
                        Err(worker_error("no completed preparation is pending"))
                    }
                };
                let _ = reply.send(result);
            }
            Request::Discard(reply) => {
                pending = PendingPreparation::Empty;
                let _ = reply.send(Ok(()));
            }
            Request::Evict(reply) => {
                pending = PendingPreparation::Empty;
                retained = None;
                let _ = reply.send(Ok(()));
            }
            Request::Stop => break,
        }
    }
}

fn prepare_evaluation(
    root: &Path,
    suite: Option<&RustSuiteExecution>,
    limits: WorkerLimits,
    view: SourceView,
    reuse: bool,
    retained: Option<&ResidentPreparation>,
    pending: &mut PendingPreparation,
) -> EvaluationReply {
    *pending = PendingPreparation::Empty;
    let prior = if reuse { retained } else { None };
    let result = prepare_resident_view(root, view, prior, suite);
    let usage = input_retention::current().unwrap_or_default();
    let result = if usage.exhausted {
        Err(parser_limit())
    } else {
        result.map_err(|error| evaluation_error(&error)).map(
            |(evaluation, mut preparation, work)| {
                let preparation_bytes = preparation.accounted_resident_bytes();
                let preparation_units = preparation.cached_unit_cardinality();
                let preparation_bytes_by_owner = preparation.accounted_bytes_by_owner();
                let retained_preparation_bytes =
                    retained.map_or(0, ResidentPreparation::accounted_resident_bytes);
                let complete_prior_owner_preparation =
                    prior.is_some_and(ResidentPreparation::complete_owner_preparation);
                let evicted = preparation
                    .retain_within_limits(limits.preparation_bytes, limits.preparation_units);
                let admitted_bytes = preparation.accounted_resident_bytes();
                let admitted_units = preparation.cached_unit_cardinality();
                let pending_program_preparation = preparation.has_program_preparation();
                let mut reasons = Vec::new();
                for (owner, was_evicted) in ["program", "domain", "effect"].into_iter().zip(evicted)
                {
                    if was_evicted {
                        reasons.push(format!("{owner}_preparation_evicted_for_retention_limit"));
                    }
                }
                if prior.is_some() && !complete_prior_owner_preparation {
                    reasons.push("incomplete_owner_preparation_requires_full_fallback".into());
                }
                if admitted_bytes > 0 {
                    *pending = PendingPreparation::Ready(Box::new(preparation));
                } else {
                    *pending = PendingPreparation::Evicted;
                    reasons.push("preparation_evicted_for_retention_limit".into());
                }
                WorkerEvaluation {
                    evaluation,
                    work,
                    preparation_bytes: admitted_bytes,
                    preparation_units: admitted_units,
                    pending_program_preparation,
                    retained_preparation_bytes,
                    complete_prior_owner_preparation,
                    preparation_bytes_before_eviction: preparation_bytes,
                    preparation_units_before_eviction: preparation_units,
                    preparation_bytes_by_owner,
                    parser_bytes: usage.admission_bytes,
                    parser_resident_charge: usage.admission_bytes * PARSER_ALLOCATION_MULTIPLIER,
                    parser_input_bytes: usage.input_bytes,
                    parser_tokenizations: usage.input_count,
                    input_bytes_tokenized: 0,
                    tokenizations: 0,
                    admission_bytes_added: 0,
                    discarded_parser_bytes: 0,
                    discarded_input_bytes: 0,
                    discarded_tokenizations: 0,
                    parser_rotated: false,
                    reasons,
                }
            },
        )
    };
    EvaluationReply {
        result,
        usage,
        exhausted: usage.exhausted,
    }
}
