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
        if !body.matches_declaration(
            self.language,
            &evaluation,
            self.source_path,
            self.source_ref,
            self.function,
        ) {
            return NativeCallableOutcome::Unavailable(
                NativeCallableLimitation::OccurrenceUnresolved,
            );
        }
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

#[cfg(test)]
mod binding_tests {
    //! Exact source and evaluation controls for native declaration links.

    use crate::program_semantics::native_body::{
        NativeBodyError, NativeBodyInput, NativeBodyLanguage, NativeBodyOutcome, NativeCallBindings,
    };
    use crate::program_semantics::native_callable::{
        NativeCallableLimitation, NativeCallableOutcome, VerifiedCallableLink,
    };
    use crate::project::EvaluationKey;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const SOURCE: &str = "def selected():\n    return True\n";
    const PATH: &str = "subject.py";
    const PIN: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CHANGED: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn literal_reply() -> Vec<u8> {
        let end = SOURCE.trim_end().len();
        let value = SOURCE.find("return").unwrap();
        let span = |start, end, line, column| {
            json!({"path":PATH,"start_byte":start,"end_byte":end,
                   "start_line":line,"start_byte_column":column})
        };
        serde_json::to_vec(&json!({
            "status":"LOWERABLE",
            "symbol":{
                "name":"selected",
                "span":span(4, 12, 1, 5),
                "declaration_span":span(0, end, 1, 1),
            },
            "parameters":[],"result_scalar":"BOOL","locals":[],
            "body":[{"kind":"return","span":span(value, end, 2, 5),
                "value":{"kind":"boolean","value":true}}],
        }))
        .unwrap()
    }

    /// `T-AF-PROGRAM-SEMANTICS-0001-R11-005`
    /// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R11
    #[test]
    fn native_callable_requires_the_retained_exact_declaration_and_evaluation() {
        let source_ref = format!("sha256:{:x}", Sha256::digest(SOURCE.as_bytes()));
        let evaluation = EvaluationKey::new(PIN, PIN, PIN);
        let input = NativeBodyInput {
            language: NativeBodyLanguage::Python,
            evaluation: &evaluation,
            exchange_ref: PIN,
            producer_ref: PIN,
            source_path: PATH,
            source_ref: &source_ref,
            source: SOURCE.as_bytes(),
            python_bool_parameters: &[],
        };
        let reply = literal_reply();
        let lower = || {
            let NativeBodyOutcome::Lowered(body) = input.admit(&reply).unwrap() else {
                panic!("the literal body must lower");
            };
            body
        };
        let exact = VerifiedCallableLink {
            language: NativeBodyLanguage::Python,
            namespace: "subject",
            function: "selected",
            source_path: PATH,
            source_ref: &source_ref,
            origin_ref: PIN,
            exchange_ref: PIN,
        };
        let refuses = |binding: VerifiedCallableLink<'_>, selected: EvaluationKey| {
            assert!(matches!(
                binding.attach(selected, lower()),
                NativeCallableOutcome::Unavailable(NativeCallableLimitation::OccurrenceUnresolved)
            ));
        };
        for changed in [
            VerifiedCallableLink {
                function: "different",
                ..exact
            },
            VerifiedCallableLink {
                source_path: "different.py",
                ..exact
            },
            VerifiedCallableLink {
                source_ref: CHANGED,
                ..exact
            },
            VerifiedCallableLink {
                language: NativeBodyLanguage::Go,
                ..exact
            },
        ] {
            refuses(changed, evaluation.clone());
        }
        for changed in [
            EvaluationKey::new(CHANGED, PIN, PIN),
            EvaluationKey::new(PIN, CHANGED, PIN),
            EvaluationKey::new(PIN, PIN, CHANGED),
        ] {
            refuses(VerifiedCallableLink { ..exact }, changed);
        }
        let NativeCallableOutcome::Linked(linked) = exact.attach(evaluation.clone(), lower())
        else {
            panic!("the independently selected declaration must link");
        };
        assert_eq!(linked.function(), "selected");
        assert_eq!(linked.source_ref(), source_ref);
        assert_eq!(linked.evaluation(), &evaluation);
    }

    const CALL_SOURCE: &str =
        "def outer():\n    def helper():\n        return True\n    return helper()\n";

    fn native_call_replies() -> (Vec<u8>, Vec<u8>) {
        let span = |start: usize, end: usize| {
            let prefix = &CALL_SOURCE[..start];
            let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
            let column = prefix.rsplit('\n').next().unwrap().len() + 1;
            json!({"path":PATH,"start_byte":start,"end_byte":end,
                   "start_line":line,"start_byte_column":column})
        };
        let inner_start = CALL_SOURCE.find("def helper").unwrap();
        let inner_end = CALL_SOURCE.find("True").unwrap() + 4;
        let inner = json!({
            "name":"helper","span":span(inner_start + 4, inner_start + 10),
            "declaration_span":span(inner_start,inner_end),
        });
        let outer_end = CALL_SOURCE.trim_end().len();
        let caller_reply = serde_json::to_vec(&json!({
            "status":"LOWERABLE",
            "symbol":{"name":"outer","span":span(4,9),"declaration_span":span(0,outer_end)},
            "parameters":[],"result_scalar":"BOOL","locals":[],
            "body":[{"kind":"return","span":span(CALL_SOURCE.rfind("return").unwrap(),outer_end),
                     "value":{"kind":"call","call":{
                        "span":span(CALL_SOURCE.rfind("helper").unwrap(),outer_end),
                        "target":inner,"arguments":[]
                     }}}],
        }))
        .unwrap();
        let target_reply = serde_json::to_vec(&json!({
            "status":"LOWERABLE","symbol":inner,
            "parameters":[],"result_scalar":"BOOL","locals":[],
            "body":[{"kind":"return","span":span(CALL_SOURCE.find("return").unwrap(),inner_end),
                     "value":{"kind":"boolean","value":true}}],
        }))
        .unwrap();
        (caller_reply, target_reply)
    }

    /// `T-AF-PROGRAM-SEMANTICS-0001-R11-006`
    /// Fortress requirement: AF-PROGRAM-SEMANTICS-0001-R11
    #[test]
    fn native_calls_reject_mixed_evaluations_exchanges_and_declarations() {
        let file_ref = format!("sha256:{:x}", Sha256::digest(CALL_SOURCE.as_bytes()));
        let evaluation = EvaluationKey::new(PIN, PIN, PIN);
        let input = NativeBodyInput {
            language: NativeBodyLanguage::Python,
            evaluation: &evaluation,
            exchange_ref: PIN,
            producer_ref: PIN,
            source_path: PATH,
            source_ref: &file_ref,
            source: CALL_SOURCE.as_bytes(),
            python_bool_parameters: &[],
        };
        let (caller_reply, target_reply) = native_call_replies();
        let lower = |scope: &NativeBodyInput<'_>, reply: &[u8]| {
            let NativeBodyOutcome::Lowered(body) = scope.admit_bound_calls(reply).unwrap() else {
                panic!("the exact Boolean fixtures must lower");
            };
            body
        };
        let caller = lower(&input, &caller_reply);
        let helper = lower(&input, &target_reply);
        let [site] = caller.bound_calls() else {
            panic!("the declared source has one call");
        };

        let rejects = |changed: &NativeBodyInput<'_>| {
            let incompatible = lower(changed, &target_reply);
            let mut bindings = NativeCallBindings::default();
            assert_eq!(
                bindings.insert(&caller, site, &file_ref, Some(&incompatible)),
                Err(NativeBodyError::InvalidResponse)
            );
            assert!(bindings.target(&caller, site).is_none());
        };
        for changed in [
            EvaluationKey::new(CHANGED, PIN, PIN),
            EvaluationKey::new(PIN, CHANGED, PIN),
            EvaluationKey::new(PIN, PIN, CHANGED),
        ] {
            rejects(&NativeBodyInput {
                evaluation: &changed,
                ..input
            });
        }
        rejects(&NativeBodyInput {
            exchange_ref: CHANGED,
            ..input
        });
        rejects(&NativeBodyInput {
            producer_ref: CHANGED,
            ..input
        });

        let drifted_source = format!("{CALL_SOURCE}# unrelated source edit\n");
        let drifted_ref = format!("sha256:{:x}", Sha256::digest(drifted_source.as_bytes()));
        rejects(&NativeBodyInput {
            source: drifted_source.as_bytes(),
            source_ref: &drifted_ref,
            ..input
        });
        let mut bindings = NativeCallBindings::default();
        assert_eq!(
            bindings.insert(&caller, site, &file_ref, Some(&caller)),
            Err(NativeBodyError::InvalidResponse)
        );
        bindings
            .insert(&caller, site, &file_ref, Some(&helper))
            .unwrap();
        assert_eq!(
            bindings.insert(&caller, site, &file_ref, None),
            Err(NativeBodyError::InvalidResponse)
        );
        assert_eq!(
            bindings.target(&caller, site).unwrap().binding(),
            helper.binding()
        );
        assert!(bindings.target(&helper, site).is_none());
    }
}
