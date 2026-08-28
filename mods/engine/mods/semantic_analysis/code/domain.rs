//! Deterministic language-neutral semantic value domains.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::program_semantics::SemanticType;

/// One inclusive integer interval.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub struct IntegerInterval {
    min: i128,
    max: i128,
}

impl IntegerInterval {
    /// Creates one nonempty inclusive interval.
    #[must_use]
    pub const fn new(min: i128, max: i128) -> Option<Self> {
        if min <= max {
            Some(Self { min, max })
        } else {
            None
        }
    }

    /// Returns the lower inclusive bound.
    #[must_use]
    pub const fn lower(self) -> i128 {
        self.min
    }

    /// Returns the upper inclusive bound.
    #[must_use]
    pub const fn upper(self) -> i128 {
        self.max
    }
}

/// A conservative subset of one PSM static type domain.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SemanticDomain {
    /// No runtime value is possible.
    Bottom {
        /// PSM static type identity.
        type_id: String,
    },
    /// Every value of the static type remains possible.
    Top {
        /// PSM static type identity.
        type_id: String,
    },
    /// A finite Boolean subset.
    Boolean {
        /// PSM static type identity.
        type_id: String,
        /// Sorted possible values.
        values: Vec<bool>,
    },
    /// A normalized integer union with finite exclusions.
    Integer {
        /// PSM static type identity.
        type_id: String,
        /// Sorted disjoint inclusive intervals.
        intervals: Vec<IntegerInterval>,
        /// Sorted values removed from the intervals.
        excluded: Vec<i128>,
    },
    /// Optional value states.
    Option {
        /// PSM static type identity.
        type_id: String,
        /// Whether `None` remains possible.
        none: bool,
        /// Possible `Some` payload; bottom means no `Some` state.
        some: Box<SemanticDomain>,
    },
    /// Result success/error states.
    Result {
        /// PSM static type identity.
        type_id: String,
        /// Possible `Ok` payload; bottom means no success state.
        ok: Box<SemanticDomain>,
        /// Possible `Err` payload; bottom means no error state.
        err: Box<SemanticDomain>,
    },
    /// Nominal enum variant subset.
    Enum {
        /// PSM static type identity.
        type_id: String,
        /// Sorted possible variants and optional payload domains.
        variants: BTreeMap<String, Option<Box<SemanticDomain>>>,
    },
    /// Ordered product domain.
    Tuple {
        /// PSM static type identity.
        type_id: String,
        /// Component domains.
        elements: Vec<SemanticDomain>,
    },
    /// An opaque named/string/static domain for which only top/bottom are known.
    Opaque {
        /// PSM static type identity.
        type_id: String,
        /// Whether every static value remains possible.
        top: bool,
    },
}

impl SemanticDomain {
    /// Returns the associated PSM static type identity.
    #[must_use]
    pub fn type_id(&self) -> &str {
        match self {
            Self::Bottom { type_id }
            | Self::Top { type_id }
            | Self::Boolean { type_id, .. }
            | Self::Integer { type_id, .. }
            | Self::Option { type_id, .. }
            | Self::Result { type_id, .. }
            | Self::Enum { type_id, .. }
            | Self::Tuple { type_id, .. }
            | Self::Opaque { type_id, .. } => type_id,
        }
    }

    /// Creates the impossible domain for one static type.
    #[must_use]
    pub fn bottom(type_id: impl Into<String>) -> Self {
        Self::Bottom {
            type_id: type_id.into(),
        }
    }

    /// Creates the full supported domain for one PSM type.
    #[must_use]
    pub fn from_static_type(type_id: impl Into<String>, semantic: &SemanticType) -> Self {
        let type_id = type_id.into();
        match semantic {
            SemanticType::Never => Self::bottom(type_id),
            SemanticType::Bool => Self::Boolean {
                type_id,
                values: vec![false, true],
            },
            SemanticType::Integer { family } => integer_bounds(family).map_or(
                Self::Top {
                    type_id: type_id.clone(),
                },
                |(min, max)| Self::Integer {
                    type_id,
                    intervals: vec![IntegerInterval { min, max }],
                    excluded: Vec::new(),
                },
            ),
            SemanticType::Option { value } => Self::Option {
                type_id,
                none: true,
                some: Box::new(Self::from_static_type(nested_type_id(value), value)),
            },
            SemanticType::Result { success, error } => Self::Result {
                type_id,
                ok: Box::new(Self::from_static_type(nested_type_id(success), success)),
                err: Box::new(Self::from_static_type(nested_type_id(error), error)),
            },
            SemanticType::Tuple { elements } => Self::Tuple {
                type_id,
                elements: elements
                    .iter()
                    .map(|element| Self::from_static_type(nested_type_id(element), element))
                    .collect(),
            },
            SemanticType::Unit
            | SemanticType::Float { .. }
            | SemanticType::Char
            | SemanticType::String { .. }
            | SemanticType::Array { .. }
            | SemanticType::Slice { .. }
            | SemanticType::Reference { .. }
            | SemanticType::Pointer { .. }
            | SemanticType::Named { .. }
            | SemanticType::GenericParameter { .. }
            | SemanticType::Function { .. }
            | SemanticType::Unknown { .. } => Self::Opaque { type_id, top: true },
        }
    }

    /// Creates one Boolean subset.
    #[must_use]
    pub fn boolean(type_id: impl Into<String>, values: impl IntoIterator<Item = bool>) -> Self {
        let mut values = values.into_iter().collect::<Vec<_>>();
        values.sort_unstable();
        values.dedup();
        if values.is_empty() {
            return Self::bottom(type_id);
        }
        Self::Boolean {
            type_id: type_id.into(),
            values,
        }
    }

    /// Creates one normalized integer domain.
    #[must_use]
    pub fn integer(
        type_id: impl Into<String>,
        intervals: impl IntoIterator<Item = IntegerInterval>,
        excluded: impl IntoIterator<Item = i128>,
    ) -> Self {
        let type_id = type_id.into();
        let intervals = normalize_intervals(intervals.into_iter().collect());
        if intervals.is_empty() {
            return Self::bottom(type_id);
        }
        let mut excluded = excluded
            .into_iter()
            .filter(|value| intervals.iter().any(|interval| contains(*interval, *value)))
            .collect::<Vec<_>>();
        excluded.sort_unstable();
        excluded.dedup();
        Self::Integer {
            type_id,
            intervals,
            excluded,
        }
        .normalize_empty_integer()
    }

    /// Returns whether no runtime value is represented.
    #[must_use]
    pub fn is_bottom(&self) -> bool {
        match self {
            Self::Bottom { .. } => true,
            Self::Boolean { values, .. } => values.is_empty(),
            Self::Integer {
                intervals,
                excluded,
                ..
            } => intervals.iter().all(|interval| {
                interval.min == interval.max && excluded.binary_search(&interval.min).is_ok()
            }),
            Self::Option { none, some, .. } => !none && some.is_bottom(),
            Self::Result { ok, err, .. } => ok.is_bottom() && err.is_bottom(),
            Self::Enum { variants, .. } => variants.is_empty(),
            Self::Tuple { elements, .. } => elements.iter().any(Self::is_bottom),
            Self::Opaque { top, .. } => !top,
            Self::Top { .. } => false,
        }
    }

    /// Returns whether the entire supported static domain is represented.
    #[must_use]
    pub fn is_top(&self) -> bool {
        matches!(self, Self::Top { .. } | Self::Opaque { top: true, .. })
    }

    /// Determines semantic subset inclusion conservatively.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        if self.type_id() != other.type_id() {
            return false;
        }
        if self.is_bottom() || other.is_top() {
            return true;
        }
        match (self, other) {
            (_, Self::Top { .. }) => true,
            (Self::Top { .. }, _) => other.is_top(),
            (Self::Boolean { values: left, .. }, Self::Boolean { values: right, .. }) => {
                left.iter().all(|value| right.binary_search(value).is_ok())
            }
            (
                Self::Integer {
                    intervals: left,
                    excluded: left_excluded,
                    ..
                },
                Self::Integer {
                    intervals: right,
                    excluded: right_excluded,
                    ..
                },
            ) => integer_subset(left, left_excluded, right, right_excluded),
            (
                Self::Option {
                    none: left_none,
                    some: left_some,
                    ..
                },
                Self::Option {
                    none: right_none,
                    some: right_some,
                    ..
                },
            ) => (!left_none || *right_none) && left_some.is_subset_of(right_some),
            (
                Self::Result {
                    ok: left_ok,
                    err: left_err,
                    ..
                },
                Self::Result {
                    ok: right_ok,
                    err: right_err,
                    ..
                },
            ) => left_ok.is_subset_of(right_ok) && left_err.is_subset_of(right_err),
            (
                Self::Enum { variants: left, .. },
                Self::Enum {
                    variants: right, ..
                },
            ) => left.iter().all(|(name, payload)| {
                right
                    .get(name)
                    .is_some_and(|required| match (payload, required) {
                        (None, None) => true,
                        (Some(value), Some(required)) => value.is_subset_of(required),
                        _ => false,
                    })
            }),
            (
                Self::Tuple { elements: left, .. },
                Self::Tuple {
                    elements: right, ..
                },
            ) => {
                left.len() == right.len()
                    && left
                        .iter()
                        .zip(right)
                        .all(|(value, required)| value.is_subset_of(required))
            }
            (Self::Opaque { top: left, .. }, Self::Opaque { top: right, .. }) => !left || *right,
            _ => false,
        }
    }

    /// Computes a conservative intersection.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn intersection(&self, other: &Self) -> Self {
        if self.type_id() != other.type_id() {
            return Self::bottom(self.type_id());
        }
        if self.is_bottom() || other.is_bottom() {
            return Self::bottom(self.type_id());
        }
        if self.is_top() {
            return other.clone();
        }
        if other.is_top() {
            return self.clone();
        }
        match (self, other) {
            (Self::Boolean { values: left, .. }, Self::Boolean { values: right, .. }) => {
                Self::boolean(
                    self.type_id(),
                    left.iter()
                        .copied()
                        .filter(|value| right.binary_search(value).is_ok()),
                )
            }
            (
                Self::Integer {
                    intervals: left,
                    excluded: left_excluded,
                    ..
                },
                Self::Integer {
                    intervals: right,
                    excluded: right_excluded,
                    ..
                },
            ) => Self::integer(
                self.type_id(),
                intersect_intervals(left, right),
                left_excluded.iter().chain(right_excluded).copied(),
            ),
            (
                Self::Option {
                    none: left_none,
                    some: left_some,
                    ..
                },
                Self::Option {
                    none: right_none,
                    some: right_some,
                    ..
                },
            ) => Self::Option {
                type_id: self.type_id().into(),
                none: *left_none && *right_none,
                some: Box::new(left_some.intersection(right_some)),
            }
            .normalize_wrapper(),
            (
                Self::Result {
                    ok: left_ok,
                    err: left_err,
                    ..
                },
                Self::Result {
                    ok: right_ok,
                    err: right_err,
                    ..
                },
            ) => Self::Result {
                type_id: self.type_id().into(),
                ok: Box::new(left_ok.intersection(right_ok)),
                err: Box::new(left_err.intersection(right_err)),
            }
            .normalize_wrapper(),
            (
                Self::Enum { variants: left, .. },
                Self::Enum {
                    variants: right, ..
                },
            ) => {
                let variants = left
                    .iter()
                    .filter_map(|(name, payload)| {
                        right
                            .get(name)
                            .and_then(|required| match (payload, required) {
                                (None, None) => Some((name.clone(), None)),
                                (Some(value), Some(required)) => {
                                    let result = value.intersection(required);
                                    (!result.is_bottom())
                                        .then_some((name.clone(), Some(Box::new(result))))
                                }
                                _ => None,
                            })
                    })
                    .collect();
                Self::Enum {
                    type_id: self.type_id().into(),
                    variants,
                }
                .normalize_wrapper()
            }
            (
                Self::Tuple { elements: left, .. },
                Self::Tuple {
                    elements: right, ..
                },
            ) if left.len() == right.len() => Self::Tuple {
                type_id: self.type_id().into(),
                elements: left
                    .iter()
                    .zip(right)
                    .map(|(left, right)| left.intersection(right))
                    .collect(),
            }
            .normalize_wrapper(),
            (Self::Opaque { top: left, .. }, Self::Opaque { top: right, .. }) => Self::Opaque {
                type_id: self.type_id().into(),
                top: *left && *right,
            },
            _ => Self::bottom(self.type_id()),
        }
    }

    /// Computes the least conservative representable union.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn join(&self, other: &Self) -> Self {
        if self.type_id() != other.type_id() {
            return Self::Top {
                type_id: self.type_id().into(),
            };
        }
        if self.is_bottom() {
            return other.clone();
        }
        if other.is_bottom() {
            return self.clone();
        }
        if self.is_top() || other.is_top() {
            return Self::Top {
                type_id: self.type_id().into(),
            };
        }
        match (self, other) {
            (Self::Boolean { values: left, .. }, Self::Boolean { values: right, .. }) => {
                Self::boolean(self.type_id(), left.iter().chain(right).copied())
            }
            (
                Self::Integer {
                    intervals: left,
                    excluded: left_excluded,
                    ..
                },
                Self::Integer {
                    intervals: right,
                    excluded: right_excluded,
                    ..
                },
            ) => {
                let excluded = left_excluded
                    .iter()
                    .filter(|value| right_excluded.binary_search(value).is_ok())
                    .copied();
                Self::integer(self.type_id(), left.iter().chain(right).copied(), excluded)
            }
            (
                Self::Option {
                    none: left_none,
                    some: left_some,
                    ..
                },
                Self::Option {
                    none: right_none,
                    some: right_some,
                    ..
                },
            ) => Self::Option {
                type_id: self.type_id().into(),
                none: *left_none || *right_none,
                some: Box::new(left_some.join(right_some)),
            },
            (
                Self::Result {
                    ok: left_ok,
                    err: left_err,
                    ..
                },
                Self::Result {
                    ok: right_ok,
                    err: right_err,
                    ..
                },
            ) => Self::Result {
                type_id: self.type_id().into(),
                ok: Box::new(left_ok.join(right_ok)),
                err: Box::new(left_err.join(right_err)),
            },
            (
                Self::Enum { variants: left, .. },
                Self::Enum {
                    variants: right, ..
                },
            ) => {
                let names = left
                    .keys()
                    .chain(right.keys())
                    .cloned()
                    .collect::<BTreeSet<_>>();
                let variants = names
                    .into_iter()
                    .map(|name| {
                        let payload = match (left.get(&name), right.get(&name)) {
                            (Some(Some(left)), Some(Some(right))) => {
                                Some(Box::new(left.join(right)))
                            }
                            (Some(payload), None) | (None, Some(payload)) => payload.clone(),
                            _ => None,
                        };
                        (name, payload)
                    })
                    .collect();
                Self::Enum {
                    type_id: self.type_id().into(),
                    variants,
                }
            }
            (
                Self::Tuple { elements: left, .. },
                Self::Tuple {
                    elements: right, ..
                },
            ) if left.len() == right.len() => Self::Tuple {
                type_id: self.type_id().into(),
                elements: left
                    .iter()
                    .zip(right)
                    .map(|(left, right)| left.join(right))
                    .collect(),
            },
            (Self::Opaque { top: left, .. }, Self::Opaque { top: right, .. }) => Self::Opaque {
                type_id: self.type_id().into(),
                top: *left || *right,
            },
            _ => Self::Top {
                type_id: self.type_id().into(),
            },
        }
    }

    /// Computes a representable counter-domain for `self \ other`.
    #[must_use]
    pub fn difference(&self, other: &Self) -> Option<Self> {
        if self.type_id() != other.type_id() || other.is_bottom() {
            return Some(self.clone());
        }
        if self.is_subset_of(other) {
            return Some(Self::bottom(self.type_id()));
        }
        match (self, other) {
            (Self::Boolean { values: left, .. }, Self::Boolean { values: right, .. }) => {
                Some(Self::boolean(
                    self.type_id(),
                    left.iter()
                        .copied()
                        .filter(|value| right.binary_search(value).is_err()),
                ))
            }
            (
                Self::Integer {
                    intervals,
                    excluded,
                    ..
                },
                Self::Integer {
                    intervals: remove,
                    excluded: restored,
                    ..
                },
            ) => {
                let mut remaining = subtract_intervals(intervals, remove);
                remaining.extend(restored.iter().filter_map(|value| {
                    contains_any(intervals, *value).then_some(IntegerInterval {
                        min: *value,
                        max: *value,
                    })
                }));
                Some(Self::integer(
                    self.type_id(),
                    remaining,
                    excluded.iter().copied(),
                ))
            }
            (
                Self::Option { none, some, .. },
                Self::Option {
                    none: remove_none,
                    some: remove_some,
                    ..
                },
            ) => Some(
                Self::Option {
                    type_id: self.type_id().into(),
                    none: *none && !remove_none,
                    some: Box::new(some.difference(remove_some)?),
                }
                .normalize_wrapper(),
            ),
            (
                Self::Result { ok, err, .. },
                Self::Result {
                    ok: remove_ok,
                    err: remove_err,
                    ..
                },
            ) => Some(
                Self::Result {
                    type_id: self.type_id().into(),
                    ok: Box::new(ok.difference(remove_ok)?),
                    err: Box::new(err.difference(remove_err)?),
                }
                .normalize_wrapper(),
            ),
            (
                Self::Enum { variants, .. },
                Self::Enum {
                    variants: remove, ..
                },
            ) => Some(
                Self::Enum {
                    type_id: self.type_id().into(),
                    variants: variants
                        .iter()
                        .filter(|(name, _)| !remove.contains_key(*name))
                        .map(|(name, payload)| (name.clone(), payload.clone()))
                        .collect(),
                }
                .normalize_wrapper(),
            ),
            _ => None,
        }
    }

    /// Applies deterministic widening for iterative analysis.
    #[must_use]
    pub fn widen(&self, next: &Self) -> Self {
        match (self, next) {
            (
                Self::Integer {
                    intervals: previous,
                    ..
                },
                Self::Integer {
                    intervals: current, ..
                },
            ) if previous != current => Self::Top {
                type_id: self.type_id().into(),
            },
            _ => self.join(next),
        }
    }

    fn normalize_empty_integer(self) -> Self {
        if self.is_bottom() {
            Self::bottom(self.type_id())
        } else {
            self
        }
    }

    fn normalize_wrapper(self) -> Self {
        if self.is_bottom() {
            Self::bottom(self.type_id())
        } else {
            self
        }
    }
}

fn integer_bounds(family: &str) -> Option<(i128, i128)> {
    match family {
        "i8" => Some((i128::from(i8::MIN), i128::from(i8::MAX))),
        "i16" => Some((i128::from(i16::MIN), i128::from(i16::MAX))),
        "i32" => Some((i128::from(i32::MIN), i128::from(i32::MAX))),
        "i64" | "isize" => Some((i128::from(i64::MIN), i128::from(i64::MAX))),
        "i128" => Some((i128::MIN, i128::MAX)),
        "u8" => Some((0, i128::from(u8::MAX))),
        "u16" => Some((0, i128::from(u16::MAX))),
        "u32" => Some((0, i128::from(u32::MAX))),
        "u64" | "usize" => Some((0, i128::from(u64::MAX))),
        "u128" => Some((0, i128::MAX)),
        _ => None,
    }
}

fn nested_type_id(semantic: &SemanticType) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(semantic).expect("semantic type identity is serializable");
    format!("type:sha256:{:x}", Sha256::digest(bytes))
}

fn normalize_intervals(mut intervals: Vec<IntegerInterval>) -> Vec<IntegerInterval> {
    intervals.sort_unstable();
    let mut result: Vec<IntegerInterval> = Vec::new();
    for interval in intervals {
        if let Some(last) = result.last_mut()
            && interval.min <= last.max.saturating_add(1)
        {
            last.max = last.max.max(interval.max);
        } else {
            result.push(interval);
        }
    }
    result
}

fn intersect_intervals(
    left: &[IntegerInterval],
    right: &[IntegerInterval],
) -> Vec<IntegerInterval> {
    let mut result = Vec::new();
    for left in left {
        for right in right {
            if let Some(interval) =
                IntegerInterval::new(left.min.max(right.min), left.max.min(right.max))
            {
                result.push(interval);
            }
        }
    }
    normalize_intervals(result)
}

fn subtract_intervals(
    source: &[IntegerInterval],
    remove: &[IntegerInterval],
) -> Vec<IntegerInterval> {
    let mut current = source.to_vec();
    for removed in remove {
        let mut next = Vec::new();
        for interval in current {
            if removed.max < interval.min || removed.min > interval.max {
                next.push(interval);
                continue;
            }
            if interval.min < removed.min {
                next.push(IntegerInterval {
                    min: interval.min,
                    max: removed.min.saturating_sub(1),
                });
            }
            if interval.max > removed.max {
                next.push(IntegerInterval {
                    min: removed.max.saturating_add(1),
                    max: interval.max,
                });
            }
        }
        current = next;
    }
    normalize_intervals(current)
}

fn integer_subset(
    left: &[IntegerInterval],
    left_excluded: &[i128],
    right: &[IntegerInterval],
    right_excluded: &[i128],
) -> bool {
    left.iter().all(|interval| {
        right
            .iter()
            .any(|candidate| candidate.min <= interval.min && candidate.max >= interval.max)
    }) && right_excluded
        .iter()
        .all(|value| !contains_any(left, *value) || left_excluded.binary_search(value).is_ok())
}

fn contains(interval: IntegerInterval, value: i128) -> bool {
    interval.min <= value && value <= interval.max
}

fn contains_any(intervals: &[IntegerInterval], value: i128) -> bool {
    intervals.iter().any(|interval| contains(*interval, value))
}
