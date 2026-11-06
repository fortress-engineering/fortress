//! Streaming `JUnit` normalization without execution, DTDs or implicit inventory.

use quick_xml::{
    Reader, XmlVersion,
    events::{BytesStart, Event},
};
use std::collections::{BTreeMap, BTreeSet};

use crate::provider::{
    InventoryKey, InventoryNamespace, MAX_PROVIDER_RECORDS, NormalizedBudget, ProviderError,
    ProviderObservation, ProviderOutcome, ProviderRunManifest, ensure, preflight,
};

pub(super) struct ParsedJunit {
    pub(super) observations: Vec<ProviderObservation>,
    pub(super) limitations: Vec<String>,
}
#[derive(Default)]
struct Counts {
    tests: u64,
    failures: u64,
    errors: u64,
    skipped: u64,
}
struct Suite {
    tag: String,
    name: Option<String>,
    package: Option<String>,
    expected: BTreeMap<String, u64>,
    actual: Counts,
}
struct Case {
    key: InventoryKey,
    outcome: ProviderOutcome,
    terminals: BTreeSet<String>,
    retry: bool,
    unknown: bool,
}
#[derive(Default)]
struct State {
    stack: Vec<String>,
    suites: Vec<Suite>,
    pending: Option<Case>,
    rows: Vec<ProviderObservation>,
    limitations: BTreeSet<String>,
    root_seen: bool,
    budget: NormalizedBudget,
}

fn invalid(detail: &str) -> ProviderError {
    ProviderError::Invalid(detail.into())
}
fn xml_char(c: char) -> bool {
    matches!(c,'\t'|'\r'|'\n'|'\u{20}'..='\u{d7ff}'|'\u{e000}'..='\u{fffd}'|'\u{10000}'..='\u{10ffff}')
}
fn supported_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && bytes.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}
fn attributes(element: &BytesStart<'_>) -> Result<BTreeMap<String, String>, ProviderError> {
    let mut result = BTreeMap::new();
    for attribute in element.attributes() {
        if result.len() >= 256 {
            return Err(ProviderError::ResourceLimit("XML attributes"));
        }
        let attribute = attribute.map_err(|_| invalid("malformed/duplicate XML attribute"))?;
        let name = attribute.key.into_inner();
        ensure(
            name.len() <= 256 && supported_name(name) && name != "xmlns",
            "unsupported XML attribute/namespace",
        )?;
        let value = attribute
            .normalized_value(XmlVersion::Explicit1_0)
            .map_err(|_| invalid("invalid XML attribute/entity"))?;
        if value.len() > 65_536 {
            return Err(ProviderError::ResourceLimit("XML attribute value"));
        }
        ensure(value.chars().all(xml_char), "invalid decoded XML character")?;
        ensure(
            result.insert(name.into(), value.into_owned()).is_none(),
            "duplicate XML attribute",
        )?;
    }
    Ok(result)
}
fn expected_counts(
    attrs: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, u64>, ProviderError> {
    let mut result = BTreeMap::new();
    for name in ["tests", "failures", "errors", "skipped"] {
        if let Some(value) = attrs.get(name) {
            ensure(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                "invalid JUnit count",
            )?;
            let value = value
                .parse::<u64>()
                .map_err(|_| invalid("unrepresentable JUnit count"))?;
            ensure(
                value <= crate::wire::MAX_EXACT_PUBLIC_INTEGER,
                "inexact JUnit count",
            )?;
            result.insert(name.into(), value);
        }
    }
    Ok(result)
}
type PackageIndex<'a> = BTreeMap<(&'a str, &'a str), Option<&'a str>>;
fn package_index(manifest: Option<&ProviderRunManifest>) -> PackageIndex<'_> {
    let mut result = PackageIndex::new();
    for member in manifest.into_iter().flat_map(|m| &m.inventory) {
        if member.key.namespace != InventoryNamespace::NativeQualified {
            continue;
        }
        if let (Some(target), Some(package)) =
            (member.key.target.as_deref(), member.key.package.as_deref())
        {
            result
                .entry((target, member.key.qualified_name.as_str()))
                .and_modify(|known| {
                    if *known != Some(package) {
                        *known = None;
                    }
                })
                .or_insert(Some(package));
        }
    }
    result
}

impl State {
    #[allow(clippy::too_many_lines)]
    fn start(
        &mut self,
        element: &BytesStart<'_>,
        packages: &PackageIndex<'_>,
    ) -> Result<(), ProviderError> {
        let name = element.name().into_inner();
        ensure(
            name.len() <= 256 && supported_name(name),
            "unsupported XML element/namespace",
        )?;
        if self.stack.len() >= 64 {
            return Err(ProviderError::ResourceLimit("XML depth"));
        }
        let attrs = attributes(element)?;
        if self.stack.is_empty() {
            ensure(
                !self.root_seen && matches!(name, "testsuite" | "testsuites"),
                "JUnit requires exactly one suite root",
            )?;
            self.root_seen = true;
        }
        match name {
            "testsuite" | "testsuites" => {
                ensure(
                    self.pending.is_none()
                        && self
                            .stack
                            .last()
                            .is_none_or(|s| matches!(s.as_str(), "testsuite" | "testsuites")),
                    "suite location",
                )?;
                ensure(
                    name != "testsuites" || self.stack.is_empty(),
                    "nested aggregate suite",
                )?;
                let target = attrs.get("name").filter(|s| !s.is_empty()).cloned();
                if name == "testsuite" && target.is_none() {
                    self.limitations
                        .insert("JUNIT_SUITE_TARGET_UNSPECIFIED".into());
                }
                if attrs.get("disabled").is_some_and(|v| v != "0") {
                    self.limitations.insert("JUNIT_DISABLED_MEMBERS".into());
                }
                let package = attrs.get("package").filter(|s| !s.is_empty()).cloned();
                self.suites.push(Suite {
                    tag: name.into(),
                    name: target,
                    package,
                    expected: expected_counts(&attrs)?,
                    actual: Counts::default(),
                });
            }
            "testcase" => {
                ensure(
                    self.pending.is_none()
                        && self.stack.last().map(String::as_str) == Some("testsuite"),
                    "case location",
                )?;
                if self.rows.len() >= MAX_PROVIDER_RECORDS {
                    return Err(ProviderError::ResourceLimit("JUnit rows"));
                }
                let suite = self
                    .suites
                    .last()
                    .ok_or_else(|| invalid("case without suite"))?;
                let raw_name = attrs
                    .get("name")
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| invalid("case has no native name"))?;
                let class = attrs.get("classname").filter(|s| !s.is_empty());
                let qualified_size = raw_name
                    .len()
                    .checked_add(class.map_or(0, |s| s.len() + 2))
                    .ok_or(ProviderError::ResourceLimit("native name"))?;
                if qualified_size > 65_536 {
                    return Err(ProviderError::ResourceLimit("native name"));
                }
                let inferred = suite.name.as_deref().and_then(|target| {
                    packages
                        .get(&(
                            target,
                            // A combined class/name is built only after its bounded size is checked.
                            raw_name.as_str(),
                        ))
                        .copied()
                        .flatten()
                });
                let qualified =
                    class.map_or_else(|| raw_name.clone(), |class| format!("{class}::{raw_name}"));
                let inferred = if class.is_some() {
                    suite.name.as_deref().and_then(|target| {
                        packages
                            .get(&(target, qualified.as_str()))
                            .copied()
                            .flatten()
                    })
                } else {
                    inferred
                };
                let package = suite.package.as_deref().or(inferred);
                if package.is_none() {
                    self.limitations.insert("JUNIT_PACKAGE_UNRESOLVED".into());
                }
                // Charge repeated suite/package names before cloning them into each row.
                self.budget.charge(256)?;
                self.budget.text(&qualified)?;
                if let Some(package) = package {
                    self.budget.text(package)?;
                }
                if let Some(target) = &suite.name {
                    self.budget.text(target)?;
                }
                let mut outcome = ProviderOutcome::Passed;
                if let Some(status) = attrs.get("status") {
                    if matches!(status.as_str(), "notrun" | "skipped") {
                        outcome = ProviderOutcome::Skipped;
                    } else if !matches!(status.as_str(), "run" | "completed") {
                        outcome = ProviderOutcome::Unknown;
                        self.limitations.insert("JUNIT_STATUS_UNINTERPRETED".into());
                    }
                }
                let retry = attrs.keys().any(|key| {
                    ["retry", "flaky", "rerun"]
                        .iter()
                        .any(|word| key.to_ascii_lowercase().contains(word))
                });
                if retry {
                    self.limitations.insert("JUNIT_RETRY_METADATA".into());
                }
                self.pending = Some(Case {
                    key: InventoryKey {
                        namespace: InventoryNamespace::NativeQualified,
                        package: package.map(str::to_owned),
                        target: suite.name.clone(),
                        qualified_name: qualified,
                    },
                    outcome,
                    terminals: BTreeSet::new(),
                    retry,
                    unknown: false,
                });
            }
            "failure" | "error" | "skipped" => {
                if self.stack.last().map(String::as_str) != Some("testcase") {
                    self.limitations
                        .insert("JUNIT_NONCASE_TERMINAL_STATE".into());
                } else if let Some(case) = &mut self.pending {
                    ensure(
                        case.terminals.is_empty(),
                        "conflicting JUnit terminal states",
                    )?;
                    ensure(
                        case.terminals.insert(name.into()),
                        "duplicate JUnit terminal state",
                    )?;
                }
            }
            "system-out" | "system-err" => {
                if !self
                    .stack
                    .last()
                    .is_some_and(|s| matches!(s.as_str(), "testcase" | "testsuite"))
                {
                    self.limitations
                        .insert("JUNIT_OUTPUT_LOCATION_UNINTERPRETED".into());
                }
            }
            "properties" => {
                if !self
                    .stack
                    .last()
                    .is_some_and(|s| matches!(s.as_str(), "testcase" | "testsuite"))
                {
                    self.limitations
                        .insert("JUNIT_PROPERTIES_LOCATION_UNINTERPRETED".into());
                }
            }
            "property" => {
                if self.stack.last().map(String::as_str) != Some("properties") {
                    self.limitations
                        .insert("JUNIT_PROPERTY_LOCATION_UNINTERPRETED".into());
                }
            }
            _ => {
                self.limitations
                    .insert("JUNIT_UNINTERPRETED_ELEMENT".into());
                if let Some(case) = &mut self.pending {
                    case.unknown = true;
                    if ["retry", "flaky", "rerun"]
                        .iter()
                        .any(|word| name.to_ascii_lowercase().contains(word))
                    {
                        case.retry = true;
                    }
                }
            }
        }
        self.stack.push(name.into());
        Ok(())
    }
    fn end(&mut self, name: &str) -> Result<(), ProviderError> {
        ensure(self.stack.pop().as_deref() == Some(name), "XML closure")?;
        if name == "testcase" {
            let mut case = self
                .pending
                .take()
                .ok_or_else(|| invalid("case closure without case"))?;
            let failed = case.terminals.contains("failure");
            let error = case.terminals.contains("error");
            let skipped =
                case.terminals.contains("skipped") || case.outcome == ProviderOutcome::Skipped;
            if case.terminals.len() > 1 || ((failed || error) && skipped) {
                self.limitations
                    .insert("JUNIT_CONFLICTING_TERMINAL_STATES".into());
            }
            case.outcome = if failed || error {
                ProviderOutcome::Failed
            } else if skipped {
                ProviderOutcome::Skipped
            } else if case.unknown {
                ProviderOutcome::Unknown
            } else {
                case.outcome
            };
            for suite in &mut self.suites {
                suite.actual.tests += 1;
                suite.actual.failures += u64::from(failed);
                suite.actual.errors += u64::from(error);
                suite.actual.skipped += u64::from(skipped);
            }
            self.rows.push(ProviderObservation {
                key: case.key,
                outcome: case.outcome,
                attempts: None,
                retry_metadata_present: case.retry,
                finding_count: None,
            });
        } else if matches!(name, "testsuite" | "testsuites") {
            let suite = self
                .suites
                .pop()
                .ok_or_else(|| invalid("suite closure without suite"))?;
            ensure(suite.tag == name, "suite closure mismatch")?;
            for (key, count) in [
                ("tests", suite.actual.tests),
                ("failures", suite.actual.failures),
                ("errors", suite.actual.errors),
                ("skipped", suite.actual.skipped),
            ] {
                if suite
                    .expected
                    .get(key)
                    .is_some_and(|expected| *expected != count)
                {
                    self.limitations
                        .insert(format!("JUNIT_DECLARED_COUNT_MISMATCH:{key}"));
                }
            }
        }
        Ok(())
    }
}

pub(super) fn parse(
    payload: &[u8],
    manifest: Option<&ProviderRunManifest>,
) -> Result<ParsedJunit, ProviderError> {
    preflight(payload)?;
    let source = std::str::from_utf8(payload).map_err(|_| invalid("JUnit requires UTF-8"))?;
    ensure(
        source.chars().all(xml_char),
        "invalid XML1.0 source character",
    )?;
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    let mut reader = Reader::from_str(source);
    reader.config_mut().enable_all_checks(true);
    reader.config_mut().expand_empty_elements = true;
    let packages = package_index(manifest);
    let mut state = State::default();
    let mut events = 0_usize;
    let mut declaration_seen = false;
    loop {
        events += 1;
        if events > 1_000_000 {
            return Err(ProviderError::ResourceLimit("XML events"));
        }
        let event = reader.read_event().map_err(|_| {
            invalid(&format!(
                "malformed XML at byte {}",
                reader.error_position()
            ))
        })?;
        match event {
            Event::Start(event) => state.start(&event, &packages)?,
            Event::End(event) => state.end(event.name().into_inner())?,
            Event::Empty(event) => {
                state.start(&event, &packages)?;
                state.end(event.name().into_inner())?;
            }
            Event::DocType(_) => {
                return Err(invalid("DTD and custom entity declarations are forbidden"));
            }
            Event::Decl(event) => {
                ensure(
                    events == 1 && !declaration_seen,
                    "XML declaration must occur once at document start",
                )?;
                declaration_seen = true;
                validate_declaration(&event)?;
            }
            Event::GeneralRef(event) => {
                ensure(!state.stack.is_empty(), "entity outside document root")?;
                let name = event.as_ref();
                if !matches!(name, "lt" | "gt" | "amp" | "apos" | "quot") {
                    let value = name
                        .strip_prefix("#x")
                        .and_then(|s| u32::from_str_radix(s, 16).ok())
                        .or_else(|| name.strip_prefix('#').and_then(|s| s.parse::<u32>().ok()));
                    ensure(
                        value.and_then(char::from_u32).is_some_and(xml_char),
                        "unknown or invalid XML entity",
                    )?;
                }
            }
            Event::Text(event) => {
                if state.stack.is_empty() {
                    ensure(
                        event.chars().all(|c| matches!(c, ' ' | '\t' | '\r' | '\n')),
                        "text outside root",
                    )?;
                }
            }
            Event::CData(_) => ensure(!state.stack.is_empty(), "CDATA outside root")?,
            Event::PI(_) => {
                state
                    .limitations
                    .insert("JUNIT_PROCESSING_INSTRUCTION_UNINTERPRETED".into());
            }
            Event::Comment(_) => {}
            Event::Eof => break,
        }
    }
    ensure(
        state.root_seen
            && state.stack.is_empty()
            && state.suites.is_empty()
            && state.pending.is_none(),
        "incomplete XML document",
    )?;
    state.rows.sort_by(|a, b| a.key.cmp(&b.key));
    ensure(
        state.rows.windows(2).all(|p| p[0].key < p[1].key),
        "duplicate or retried native testcase identity",
    )?;
    Ok(ParsedJunit {
        observations: state.rows,
        limitations: state.limitations.into_iter().collect(),
    })
}

fn validate_declaration(event: &quick_xml::events::BytesDecl<'_>) -> Result<(), ProviderError> {
    let start = BytesStart::from_content(event.as_ref(), 3);
    let attrs = attributes(&start)?;
    ensure(
        attrs.get("version").is_some_and(|s| s == "1.0")
            && attrs
                .keys()
                .all(|k| matches!(k.as_str(), "version" | "encoding" | "standalone")),
        "unsupported XML declaration",
    )?;
    ensure(
        attrs
            .get("encoding")
            .is_none_or(|s| s.eq_ignore_ascii_case("utf-8")),
        "JUnit encoding is not UTF-8",
    )?;
    ensure(
        attrs
            .get("standalone")
            .is_none_or(|s| matches!(s.as_str(), "yes" | "no")),
        "invalid standalone declaration",
    )?;
    let order = start
        .attributes()
        .map(|a| {
            a.map(|a| a.key.into_inner().to_owned())
                .map_err(|_| invalid("declaration attributes"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ensure(
        order.first().is_some_and(|s| s == "version")
            && order
                .iter()
                .position(|s| s == "encoding")
                .zip(order.iter().position(|s| s == "standalone"))
                .is_none_or(|(a, b)| a <= b),
        "XML declaration attribute order",
    )?;
    Ok(())
}
