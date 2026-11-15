//! Bounded operational configuration for the independent comparison campaign.
use fortress_core::session::SessionOptions;
use std::error::Error;
use std::io;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_ACCOUNTED_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const ACTUAL_SAMPLES: usize = 100;

#[derive(Clone, Copy)]
enum Kind {
    Full,
    Development,
    Fixtures,
}

#[derive(Clone, Copy)]
pub(super) struct Campaign {
    kind: Kind,
    accounted_bytes: usize,
}

impl Campaign {
    pub(super) fn from_arguments(arguments: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut arguments = arguments.into_iter();
        let mut kind = Kind::Full;
        let mut selected_kind = false;
        let mut accounted_bytes = None;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--development-probe" | "--fixture-development-probe" if !selected_kind => {
                    kind = if argument == "--development-probe" {
                        Kind::Development
                    } else {
                        Kind::Fixtures
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
        matches!(self.kind, Kind::Full)
    }

    pub(super) const fn actual_samples(self) -> usize {
        match self.kind {
            Kind::Full => ACTUAL_SAMPLES,
            Kind::Development => 2,
            Kind::Fixtures => 0,
        }
    }

    pub(super) const fn fixture_samples(self, full: usize) -> usize {
        match self.kind {
            Kind::Full => full,
            Kind::Development | Kind::Fixtures => 1,
        }
    }

    pub(super) const fn expected_comparisons(self) -> usize {
        match self.kind {
            Kind::Full => 300,
            Kind::Development => 8,
            Kind::Fixtures => 6,
        }
    }

    pub(super) const fn name(self) -> &'static str {
        match self.kind {
            Kind::Full => "registered_full_benchmark",
            Kind::Development => "development_probe_only",
            Kind::Fixtures => "fixture_development_probe_only",
        }
    }
}
