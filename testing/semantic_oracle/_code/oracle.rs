//! Restricted fixture-language reference semantics, independent of Fortress.
//!
//! Operations describe potential effects under the qualification protocol's
//! explicit primitive contracts; these bits do not assert runtime execution.

/// No potential effect in the restricted pure instruction.
pub const NO_EFFECT: u8 = 0;
/// A filesystem-write primitive appears on a supported reachable path.
pub const FILESYSTEM_WRITE: u8 = 1;
/// A process-spawn primitive appears on a supported reachable path.
pub const PROCESS_SPAWN: u8 = 2;
/// The restricted instruction has an unresolved effect upper bound.
pub const UNKNOWN_EFFECT: u8 = 4;

/// An authored authorization; it is not negative conformance evidence.
pub const AUTHORIZATION: u8 = 0;
/// An independently known positive contradiction.
pub const SUPPORTED_VIOLATION: u8 = 1;
/// Complete restricted-source semantics support a negative conclusion.
pub const NO_SUPPORTED_VIOLATION: u8 = 2;
/// Relevant evidence is incomplete.
pub const NOT_EVALUABLE: u8 = 3;
/// No evaluative policy applies.
pub const NOT_APPLICABLE: u8 = 4;
/// Invalid authored policy in the restricted fixture protocol.
pub const INVALID_POLICY: u8 = 5;
/// No evaluative claim exists because the Module did not author a policy.
pub const NO_DECLARED_CLAIM: u8 = 6;

/// Interprets one frozen fixture opcode using only primitive pure operations.
#[must_use]
pub const fn instruction_effect(opcode: u8) -> u8 {
    match opcode {
        0 => NO_EFFECT,
        1 => FILESYSTEM_WRITE,
        2 => PROCESS_SPAWN,
        _ => UNKNOWN_EFFECT,
    }
}

/// Computes the reference effect union of two restricted fixture instructions.
///
/// Reachability is a fixture-language input whose emitted Rust encoding and
/// compiler/reference justification must be retained by the driver. The
/// oracle never asks Fortress which source path is reachable.
#[must_use]
pub const fn expected_effects(first: u8, second: u8, second_reachable: bool) -> u8 {
    let left = instruction_effect(first);
    if second_reachable {
        match (left, instruction_effect(second)) {
            (NO_EFFECT, right) | (right, NO_EFFECT) => right,
            (FILESYSTEM_WRITE, FILESYSTEM_WRITE) => FILESYSTEM_WRITE,
            (PROCESS_SPAWN, PROCESS_SPAWN) => PROCESS_SPAWN,
            (FILESYSTEM_WRITE, PROCESS_SPAWN) | (PROCESS_SPAWN, FILESYSTEM_WRITE) => 3,
            (FILESYSTEM_WRITE, UNKNOWN_EFFECT) | (UNKNOWN_EFFECT, FILESYSTEM_WRITE) => 5,
            (PROCESS_SPAWN, UNKNOWN_EFFECT) | (UNKNOWN_EFFECT, PROCESS_SPAWN) => 6,
            _ => UNKNOWN_EFFECT,
        }
    } else {
        left
    }
}

/// Applies the predeclared policy truth table to independently known effects.
///
/// `disposition` is 0 for absent policy, 1 for ALLOW and 2 for DENY. Missing
/// source coverage never supplies favorable evidence. A complete independent
/// positive witness survives an unrelated unknown alternative.
/// Effect sets are the closed three-bit protocol domain `0..=7`; other DENY
/// inputs are invalid rather than favorable absence evidence.
#[must_use]
pub const fn expected_truth(
    disposition: u8,
    denied_effect: u8,
    effects: u8,
    has_governed_subject: bool,
    has_usable_support: bool,
    source_complete: bool,
) -> u8 {
    match disposition {
        0 => NO_DECLARED_CLAIM,
        1 => AUTHORIZATION,
        2 => match denied_effect {
            FILESYSTEM_WRITE | PROCESS_SPAWN => match effects {
                0..=7 => match (has_governed_subject, has_usable_support) {
                    (false, _) => NOT_APPLICABLE,
                    (true, false) => NOT_EVALUABLE,
                    (true, true) => match (denied_effect, effects) {
                        (FILESYSTEM_WRITE, 1 | 3 | 5 | 7) | (PROCESS_SPAWN, 2 | 3 | 6 | 7) => {
                            SUPPORTED_VIOLATION
                        }
                        _ => match (source_complete, effects) {
                            (true, 0..=3) => NO_SUPPORTED_VIOLATION,
                            _ => NOT_EVALUABLE,
                        },
                    },
                },
                _ => INVALID_POLICY,
            },
            _ => INVALID_POLICY,
        },
        _ => INVALID_POLICY,
    }
}

/// Determines whether an independently supported positive has production support.
#[must_use]
pub const fn expected_blocking(truth: u8, production_witness_complete: bool) -> bool {
    match truth {
        SUPPORTED_VIOLATION => production_witness_complete,
        _ => false,
    }
}
