//! Independently literal primitive-language controls, without Fortress imports.

use fortress_semantic_oracle::{
    expected_blocking, expected_effects, expected_truth, instruction_effect,
};

/// `T-AF-SEMANTIC-ORACLE-0001-R01-001`
/// Fortress requirement: AF-SEMANTIC-ORACLE-0001-R01
#[test]
fn primitive_operations_and_reachability_have_literal_reference_meaning() {
    for (opcode, expected) in [(0, 0), (1, 1), (2, 2), (3, 4), (255, 4)] {
        assert_eq!(instruction_effect(opcode), expected);
    }
    assert_eq!(expected_effects(1, 2, true), 3);
    assert_eq!(expected_effects(1, 2, false), 1);
    assert_eq!(expected_effects(3, 1, true), 5);
    assert_eq!(expected_effects(0, 0, true), 0);
}

/// `T-AF-SEMANTIC-ORACLE-0001-R01-002`
/// Fortress requirement: AF-SEMANTIC-ORACLE-0001-R01
#[test]
fn independent_policy_table_preserves_authority_unknowns_and_nonvacuity() {
    // Expected numbers are literal protocol states, not another evaluator's output.
    for (disposition, effect, effects, subject, support, complete, expected) in [
        (0, 1, 1, true, true, true, 6),
        (1, 1, 1, true, true, true, 0),
        (3, 1, 0, true, true, true, 5),
        (2, 3, 0, true, true, true, 5),
        (2, 1, 0, false, false, true, 4),
        (2, 1, 0, true, false, true, 3),
        (2, 1, 5, true, true, true, 1),
        (2, 2, 6, true, true, true, 1),
        (2, 1, 2, true, true, true, 2),
        (2, 2, 1, true, true, true, 2),
        (2, 1, 4, true, true, true, 3),
        (2, 1, 0, true, true, false, 3),
        (2, 1, 8, true, true, true, 5),
    ] {
        assert_eq!(
            expected_truth(disposition, effect, effects, subject, support, complete),
            expected
        );
    }
    assert!(expected_blocking(1, true));
    assert!(!expected_blocking(1, false));
    for truth in [0, 2, 3, 4, 5, 6] {
        assert!(!expected_blocking(truth, true));
    }
}
