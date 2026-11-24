//! Linked callable declaration evidence outside canonical Program Semantics assembly.

use super::canonical_fact_id;
use super::native_body::{NativeBodyLanguage, NativeScalar, NativeScalarBody, digest};
use crate::implementation_observation::SourceOwnership;
use crate::project::EvaluationKey;

/// Validates the scoped native slot reference spelling without resolving it.
#[must_use]
pub fn valid_slot_reference(language: NativeBodyLanguage, reference: &str) -> bool {
    reference
        .strip_prefix(slot_namespace(language))
        .and_then(|suffix| suffix.strip_prefix(':'))
        .is_some_and(digest)
}

const fn slot_namespace(language: NativeBodyLanguage) -> &'static str {
    match language {
        NativeBodyLanguage::Go => "go_callable_slot:v1",
        NativeBodyLanguage::Python => "python_lexical_callable_slot:v1",
    }
}

/// Why a selected actual callable cannot be linked under the admitted scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeCallableLimitation {
    /// The selected declaration or source module is absent from the admissible scope.
    MissingSubject,
    /// Multiple declarations or origins prevented a unique selection.
    AmbiguousSubject,
    /// The module, package, interface, or host scope is outside this observation.
    UnsupportedScope,
    /// The admitted compiler did not establish a supported scalar body.
    BodyUnavailable,
    /// The admitted package and body observations establish different occurrences.
    OccurrenceUnresolved,
}

/// A bounded observation of the link between an actual declaration and its body.
#[derive(Debug)]
pub enum NativeCallableOutcome {
    /// Source-bound declaration and lowered body referenced the same occurrence.
    Linked(Box<LinkedNativeCallable>),
    /// The selected scope cannot establish a callable link.
    Unavailable(NativeCallableLimitation),
}

/// One source declaration linked to its supported lowered scalar body.
///
/// The slot names a declaration within its language namespace. Its occurrence
/// and evaluation bind the exact current evidence. This record provides no
/// invocation, enforcement, authorization, or certification authority.
#[derive(Debug)]
pub struct LinkedNativeCallable {
    language: NativeBodyLanguage,
    namespace: String,
    function: String,
    source_path: String,
    source_ref: String,
    slot_ref: String,
    link_ref: String,
    origin_ref: String,
    exchange_ref: String,
    evaluation: EvaluationKey,
    body: Box<NativeScalarBody>,
    declared_owner: Option<SourceOwnership>,
}

impl LinkedNativeCallable {
    /// Returns the producer's admitted language.
    #[must_use]
    pub const fn language(&self) -> NativeBodyLanguage {
        self.language
    }

    /// Returns the closed Go package path or the selected Python lexical module.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the exact declared name within the namespace.
    #[must_use]
    pub fn function(&self) -> &str {
        &self.function
    }

    /// Returns the exact repository-relative declaration file.
    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    /// Returns the digest of the exact declaration file.
    #[must_use]
    pub fn source_ref(&self) -> &str {
        &self.source_ref
    }

    /// Returns the language-scoped declaration slot reference.
    #[must_use]
    pub fn slot_ref(&self) -> &str {
        &self.slot_ref
    }

    /// Returns the exact source, authority, origin, and body linkage reference.
    #[must_use]
    pub fn link_ref(&self) -> &str {
        &self.link_ref
    }

    /// Returns the exact admitted native namespace selection identity.
    #[must_use]
    pub fn origin_ref(&self) -> &str {
        &self.origin_ref
    }

    /// Returns the exact observed body exchange identity.
    #[must_use]
    pub fn exchange_ref(&self) -> &str {
        &self.exchange_ref
    }

    /// Returns the exact evaluation key for the underlying admitted body.
    #[must_use]
    pub const fn evaluation(&self) -> &EvaluationKey {
        &self.evaluation
    }

    /// Returns independently resolved original source ownership when available.
    #[must_use]
    pub const fn declared_source_owner(&self) -> Option<&SourceOwnership> {
        self.declared_owner.as_ref()
    }

    pub(crate) fn record_original_owner(&mut self, owner: Option<SourceOwnership>) {
        self.link_ref =
            canonical_fact_id("native_callable_owned_link:v1", &(&self.link_ref, &owner));
        self.declared_owner = owner;
    }

    /// Returns the exact supported body and its transient occurrence identity.
    #[must_use]
    pub const fn body(&self) -> &NativeScalarBody {
        &self.body
    }
}

#[derive(serde::Serialize)]
pub(crate) struct VerifiedCallableLink<'a> {
    pub(crate) language: NativeBodyLanguage,
    pub(crate) namespace: &'a str,
    pub(crate) function: &'a str,
    pub(crate) source_path: &'a str,
    pub(crate) source_ref: &'a str,
    pub(crate) origin_ref: &'a str,
    pub(crate) exchange_ref: &'a str,
}

impl VerifiedCallableLink<'_> {
    pub(crate) fn attach(
        self,
        evaluation: EvaluationKey,
        body: Box<NativeScalarBody>,
    ) -> NativeCallableOutcome {
        let slot_ref = match self.language {
            NativeBodyLanguage::Go => {
                let parameters = body
                    .parameters()
                    .iter()
                    .map(|(_, scalar)| *scalar)
                    .collect::<Vec<_>>();
                if !parameters
                    .iter()
                    .copied()
                    .chain([body.result()])
                    .all(go_scalar)
                {
                    return NativeCallableOutcome::Unavailable(
                        NativeCallableLimitation::UnsupportedScope,
                    );
                }
                canonical_fact_id(
                    slot_namespace(self.language),
                    &(self.namespace, self.function, parameters, body.result()),
                )
            }
            NativeBodyLanguage::Python => {
                // Scalar v1 does not distinguish positional-only and keyword slots.
                if !body.parameters().is_empty() {
                    return NativeCallableOutcome::Unavailable(
                        NativeCallableLimitation::UnsupportedScope,
                    );
                }
                canonical_fact_id(
                    slot_namespace(self.language),
                    &(self.namespace, self.function),
                )
            }
        };
        let link_ref = canonical_fact_id(
            "native_callable_link:v1",
            &(&self, &slot_ref, &evaluation, body.binding()),
        );
        NativeCallableOutcome::Linked(Box::new(LinkedNativeCallable {
            language: self.language,
            namespace: self.namespace.into(),
            function: self.function.into(),
            source_path: self.source_path.into(),
            source_ref: self.source_ref.into(),
            slot_ref,
            link_ref,
            origin_ref: self.origin_ref.into(),
            exchange_ref: self.exchange_ref.into(),
            evaluation,
            body,
            declared_owner: None,
        }))
    }
}

fn go_scalar(value: NativeScalar) -> bool {
    matches!(value, NativeScalar::Bool | NativeScalar::SignedI64)
}
