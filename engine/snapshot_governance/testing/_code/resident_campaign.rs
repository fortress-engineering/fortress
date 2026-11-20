//! Bounded operational configuration for the independent comparison campaign.
use fortress_core::session::SessionOptions;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::io;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_ACCOUNTED_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const ACTUAL_SAMPLES: usize = 100;

#[derive(Clone, Copy)]
enum Kind {
    Core,
    Historical,
    Development,
    Fixtures,
    RegisteredFixtures,
    Endurance,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Scenario {
    BaselineRefresh,
    PathPredicateBody,
    ReadBudgetBody,
    InterproceduralDependency,
    AuthorityInvalidation,
    BaselineAfterCandidates,
    LocalBody,
    Signature,
    DependencyInput,
    UnavailablePreparation,
    CalleeBody,
    FilesystemEffect,
    TransitiveInvalidation,
    UnresolvedRelationship,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selection {
    pub(super) protocol: String,
    pub(super) actual: Vec<Scenario>,
    pub(super) fixture_sizes: Vec<usize>,
    pub(super) independent: Vec<Scenario>,
    pub(super) graph: Vec<Scenario>,
    pub(super) lifecycle_operations: BTreeMap<String, usize>,
    pub(super) differential_corpora: BTreeMap<String, usize>,
}

impl Selection {
    pub(super) fn registered() -> Result<Self> {
        Ok(serde_json::from_slice(Self::source())?)
    }

    pub(super) const fn source() -> &'static [u8] {
        include_bytes!("../_data/resident_campaign_v2.json")
    }

    pub(super) fn core_count(&self) -> usize {
        self.actual.len() + self.fixture_sizes.len() * (self.independent.len() + self.graph.len())
    }
}

#[derive(Clone, Copy)]
pub(super) struct Campaign {
    kind: Kind,
    accounted_bytes: usize,
}

impl Campaign {
    pub(super) fn from_arguments(arguments: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut arguments = arguments.into_iter();
        let mut kind = Kind::Core;
        let mut selected_kind = false;
        let mut accounted_bytes = None;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--core"
                | "--historical-300"
                | "--development-probe"
                | "--fixture-development-probe"
                | "--registered-fixture-probe"
                | "--endurance"
                    if !selected_kind =>
                {
                    kind = match argument.as_str() {
                        "--core" => Kind::Core,
                        "--historical-300" => Kind::Historical,
                        "--development-probe" => Kind::Development,
                        "--fixture-development-probe" => Kind::Fixtures,
                        "--registered-fixture-probe" => Kind::RegisteredFixtures,
                        "--endurance" => Kind::Endurance,
                        _ => unreachable!(),
                    };
                    selected_kind = true;
                }
                "--accounted-bytes" if accounted_bytes.is_none() => {
                    let value = arguments
                        .next()
                        .ok_or_else(|| io::Error::other("missing allocation account"))?;
                    let bytes = value.parse::<u64>()?;
                    if !(1..=MAX_ACCOUNTED_BYTES).contains(&bytes) {
                        return Err(io::Error::other(
                            "allocation account outside operational bounds",
                        )
                        .into());
                    }
                    accounted_bytes = Some(usize::try_from(bytes)?);
                }
                _ => return Err(io::Error::other("unknown or conflicting campaign option").into()),
            }
        }
        Ok(Self {
            kind,
            accounted_bytes: accounted_bytes
                .unwrap_or_else(|| SessionOptions::default().limits.max_accounted_bytes),
        })
    }

    pub(super) const fn accounted_bytes(self) -> usize {
        self.accounted_bytes
    }

    pub(super) const fn is_full(self) -> bool {
        matches!(self.kind, Kind::Core | Kind::Historical)
    }

    pub(super) const fn is_core(self) -> bool {
        matches!(self.kind, Kind::Core)
    }

    pub(super) const fn is_endurance(self) -> bool {
        matches!(self.kind, Kind::Endurance)
    }

    pub(super) const fn uses_registered_fixtures(self) -> bool {
        matches!(self.kind, Kind::Core | Kind::RegisteredFixtures)
    }

    pub(super) const fn actual_samples(self) -> usize {
        match self.kind {
            Kind::Core => 6,
            Kind::Historical => ACTUAL_SAMPLES,
            Kind::Development => 2,
            Kind::Fixtures | Kind::RegisteredFixtures | Kind::Endurance => 0,
        }
    }

    pub(super) const fn fixture_samples(self, full: usize) -> usize {
        match self.kind {
            Kind::Core | Kind::RegisteredFixtures => 4,
            Kind::Historical => full,
            Kind::Development | Kind::Fixtures => 1,
            Kind::Endurance => 0,
        }
    }

    pub(super) const fn expected_comparisons(self) -> usize {
        match self.kind {
            Kind::Core => 30,
            Kind::Historical => 300,
            Kind::Development => 8,
            Kind::Fixtures => 6,
            Kind::RegisteredFixtures => 24,
            Kind::Endurance => 0,
        }
    }

    pub(super) const fn name(self) -> &'static str {
        match self.kind {
            Kind::Core => "registered_core_equivalence_v2",
            Kind::Historical => "historical_300_observation",
            Kind::Development => "development_probe_only",
            Kind::Fixtures => "fixture_development_probe_only",
            Kind::RegisteredFixtures => "registered_fixture_probe_only",
            Kind::Endurance => "registered_lifecycle_endurance_v2",
        }
    }
}
