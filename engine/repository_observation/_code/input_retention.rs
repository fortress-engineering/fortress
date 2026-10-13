//! Thread-local admission for parsers which retain their input behind local handles.
//!
//! This records operational allocation units only. It has no source, language,
//! policy, model, or publication authority and is inactive for ordinary callers.

use std::cell::RefCell;
use std::fmt;

const INPUT_METADATA_BYTES: usize = 64;

/// Exact input counters and conservative operational admission units.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct InputRetentionState {
    pub(crate) input_bytes: usize,
    pub(crate) input_count: usize,
    pub(crate) admission_bytes: usize,
    pub(crate) exhausted: bool,
}

struct Budget {
    maximum: usize,
    state: InputRetentionState,
}

thread_local! {
    static RETENTION: RefCell<Option<Budget>> = const { RefCell::new(None) };
}

/// Exhaustion of an enabled local retained-input admission limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InputRetentionLimit;

impl fmt::Display for InputRetentionLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("retained input admission limit exceeded")
    }
}

/// Enables a fresh budget on a dedicated thread with no prior retained inputs.
/// Replacing an active budget is rejected rather than forgetting live allocations.
pub(crate) fn begin(maximum: usize) -> Result<(), InputRetentionLimit> {
    RETENTION.with(|retention| {
        let mut retention = retention.borrow_mut();
        if maximum == 0 || retention.is_some() {
            return Err(InputRetentionLimit);
        }
        *retention = Some(Budget {
            maximum,
            state: InputRetentionState::default(),
        });
        Ok(())
    })
}

/// Returns all charged inputs, including allocations from unsuccessful parses.
pub(crate) fn current() -> Option<InputRetentionState> {
    RETENTION.with(|retention| retention.borrow().as_ref().map(|budget| budget.state))
}

/// Reserves an input before a producer can retain it. An inactive budget is a no-op.
/// A separator and fixed metadata reserve prevent empty-input allocation bypass.
pub(crate) fn preflight_input(byte_count: usize) -> Result<(), InputRetentionLimit> {
    RETENTION.with(|retention| {
        let mut retention = retention.borrow_mut();
        let Some(budget) = retention.as_mut() else {
            return Ok(());
        };
        let next = byte_count
            .checked_add(1 + INPUT_METADATA_BYTES)
            .and_then(|input| budget.state.admission_bytes.checked_add(input));
        if budget.state.exhausted || next.is_none_or(|next| next > budget.maximum) {
            budget.state.exhausted = true;
            return Err(InputRetentionLimit);
        }
        let input_bytes = budget.state.input_bytes.checked_add(byte_count);
        let input_count = budget.state.input_count.checked_add(1);
        let (Some(input_bytes), Some(input_count), Some(admission_bytes)) =
            (input_bytes, input_count, next)
        else {
            budget.state.exhausted = true;
            return Err(InputRetentionLimit);
        };
        budget.state.input_bytes = input_bytes;
        budget.state.input_count = input_count;
        budget.state.admission_bytes = admission_bytes;
        Ok(())
    })
}
