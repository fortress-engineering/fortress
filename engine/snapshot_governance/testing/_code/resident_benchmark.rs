//! Separately executed empirical comparison over the public resident API.
//!
//! Run the prebuilt example from the repository root after source is frozen,
//! with no compiler or qualification issuer running. Records remain outside
//! application source and disposable compiler storage. This executable is not
//! a Rust test or an execution-evidence substitute.

#[path = "resident_comparison.rs"]
mod resident_comparison;

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fortress_core::bootstrap::{
    BootstrapDiscoveryOptions, apply_repository_bootstrap, discover_repository_bootstrap,
};
use fortress_core::observation::ChangeOperation;
use fortress_core::runtime_storage::{StoragePolicy, StorageReport};
use fortress_core::session::{
    Generation, Session, SessionDisposition, SessionError, SessionOptions, SessionWork, SourceDelta,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use resident_comparison::{
    ComparisonSnapshot, MAX_COMPARISON_SCRATCH_BYTES, checked_scratch_sum, context,
    value_allocation_bytes,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_REPORT_BYTES: usize = 128 * 1024 * 1024;
const ACTUAL_SAMPLES: usize = 100;
const FIXTURE_SIZES: [(usize, usize); 3] = [(32, 34), (128, 33), (512, 33)];
const GROUP_SIZE: usize = 16;
const ACTUAL_PATH: &str = "engine/repository_observation/_code/observation.rs";
const ACTUAL_NEEDLE: &str = "!value.is_empty()";
const MAX_COLLECTOR_BYTES: usize = 1024 * 1024;
const MIN_COMPARISON_METRICS_BYTES: usize = 4 * 1024 * 1024;
const COMPARISON_METRICS_COPIES: usize = 16;
const COLLECTOR_TIMEOUT: Duration = Duration::from_secs(30);
const COLLECTOR_REAP_TIMEOUT: Duration = Duration::from_secs(10);
const CANCELLATION_REQUEST: &[u8] = b"fortress-resident-benchmark-cancel-v1\n";

#[derive(Clone, Copy)]
enum Campaign {
    Full,
    DevelopmentProbe,
    FixtureDevelopmentProbe,
}

impl Campaign {
    fn parse() -> Result<Self> {
        let mut arguments = std::env::args().skip(1);
        let campaign = match arguments.next().as_deref() {
            None => Self::Full,
            Some("--development-probe") => Self::DevelopmentProbe,
            Some("--fixture-development-probe") => Self::FixtureDevelopmentProbe,
            Some(_) => {
                return Err(failure(
                    "expected no arguments, --development-probe or --fixture-development-probe",
                ));
            }
        };
        if arguments.next().is_some() {
            return Err(failure("unexpected extra benchmark argument"));
        }
        Ok(campaign)
    }

    const fn actual_samples(self) -> usize {
        match self {
            Self::Full => ACTUAL_SAMPLES,
            Self::DevelopmentProbe => 2,
            Self::FixtureDevelopmentProbe => 0,
        }
    }

    const fn fixture_samples(self, full: usize) -> usize {
        match self {
            Self::Full => full,
            Self::DevelopmentProbe | Self::FixtureDevelopmentProbe => 1,
        }
    }

    const fn expected_comparisons(self) -> usize {
        match self {
            Self::Full => 300,
            Self::DevelopmentProbe => 8,
            Self::FixtureDevelopmentProbe => 6,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Full => "registered_full_benchmark",
            Self::DevelopmentProbe => "development_probe_only",
            Self::FixtureDevelopmentProbe => "fixture_development_probe_only",
        }
    }
}

fn failure(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::other(message.into()).into()
}

struct Retention {
    started: Instant,
    root: PathBuf,
    raw: File,
    events: File,
    bytes: usize,
    last_phase: Value,
    collector_sequence: usize,
    collector_failures: Vec<Value>,
    unresolved_collectors: Vec<CollectorJob>,
}

impl Retention {
    fn new(started: Instant) -> Result<Self> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|error| failure(error.to_string()))?;
        let mut nonce = String::with_capacity(32);
        for byte in random {
            write!(nonce, "{byte:02x}")?;
        }
        let parent = std::env::temp_dir().join("fortress-qualification/session-benchmark");
        fs::create_dir_all(&parent)?;
        let root = parent.join(nonce);
        fs::create_dir(&root)?;
        let raw = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("samples.jsonl"))?;
        let events = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("events.jsonl"))?;
        Ok(Self {
            started,
            root,
            raw,
            events,
            bytes: 0,
            last_phase: Value::Null,
            collector_sequence: 0,
            collector_failures: Vec::new(),
            unresolved_collectors: Vec::new(),
        })
    }

    fn charge(&mut self, amount: usize) -> Result<()> {
        let bytes = self
            .bytes
            .checked_add(amount)
            .ok_or_else(|| failure("report size overflow"))?;
        if bytes > MAX_REPORT_BYTES {
            return Err(failure("external benchmark records exceed 128 MiB"));
        }
        self.bytes = bytes;
        Ok(())
    }

    fn append(&mut self, record: &Value) -> Result<()> {
        let mut bytes = serde_json::to_vec(record)?;
        bytes.push(b'\n');
        self.charge(bytes.len())?;
        self.raw.write_all(&bytes)?;
        self.raw.flush()?;
        Ok(())
    }

    fn document(&mut self, name: &str, record: &Value) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(record)?;
        self.charge(bytes.len())?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.root.join(name))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn phase(&mut self, active: &ActiveCase<'_>, phase: &str, proposal: &Value) -> Result<()> {
        let record = json!({"workload":active.class,"case_id":active.identity,
            "repository_root":active.root,"base_subject":active.base_subject,
            "elapsed_since_run_start_ns":elapsed(self.started)?,
            "phase":phase,"proposal":proposal});
        self.last_phase = record.clone();
        let mut bytes = serde_json::to_vec(&record)?;
        bytes.push(b'\n');
        self.charge(bytes.len())?;
        self.events.write_all(&bytes)?;
        self.events.sync_all()?;
        self.check_cancellation()
    }

    fn check_cancellation(&self) -> Result<()> {
        let path = self.root.join("cancel.request");
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 {
            return Err(failure(
                "invalid benchmark cancellation request; run is incomplete",
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(failure(
                    "reparse benchmark cancellation request; run is incomplete",
                ));
            }
        }
        let mut bytes = Vec::with_capacity(64);
        File::open(path)?.take(65).read_to_end(&mut bytes)?;
        if bytes != CANCELLATION_REQUEST {
            return Err(failure(
                "unrecognized benchmark cancellation request; run is incomplete",
            ));
        }
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "benchmark cancellation requested",
        )
        .into())
    }

    fn collector_summary(&self) -> Value {
        json!({"attempted_collectors":self.collector_sequence,
            "failed_collectors":self.collector_failures,
            "unresolved_owned_collector_jobs":self.unresolved_collectors.len(),
            "scope":"diagnostic collector lifetime is separate from Session storage; a reaped direct child does not prove descendant absence"})
    }
}

#[derive(Default)]
struct Distribution {
    warm_ns: Vec<u64>,
    cold_api_ns: Vec<u64>,
    cold_view_ns: Vec<u64>,
    resident_bytes: Vec<u64>,
    dispositions: BTreeMap<String, usize>,
    fallback_reasons: BTreeMap<String, usize>,
    work_unit_totals: BTreeMap<String, usize>,
}

#[derive(Default)]
struct Measurements {
    classes: BTreeMap<String, Distribution>,
    passed: usize,
    restored: usize,
    restoration_wall_time_ns: u64,
    post_warm_harness_wall_time_ns: u64,
    lifetime_peak_bytes: u64,
    maximum_comparison_scratch_bytes: usize,
}

impl Measurements {
    fn record(
        &mut self,
        class: &str,
        warm: &WarmMetrics,
        cold_api: &WarmMetrics,
        cold_view: u64,
        memory: &Value,
    ) -> Result<()> {
        let rss = memory["resident_bytes"]
            .as_u64()
            .ok_or_else(|| failure("missing measured RSS"))?;
        let peak = memory["lifetime_peak_resident_bytes"]
            .as_u64()
            .ok_or_else(|| failure("missing measured process peak"))?;
        let distribution = self.classes.entry(class.into()).or_default();
        distribution.warm_ns.push(warm.elapsed_ns);
        distribution.cold_api_ns.push(cold_api.elapsed_ns);
        distribution.cold_view_ns.push(cold_view);
        distribution.resident_bytes.push(rss);
        for (kind, sample) in [("warm", warm), ("cold_api", cold_api)] {
            *distribution
                .dispositions
                .entry(format!("{kind}:{:?}", sample.disposition))
                .or_default() += 1;
            for reason in &sample.reasons {
                *distribution
                    .fallback_reasons
                    .entry(format!("{kind}:{reason}"))
                    .or_default() += 1;
            }
            for (unit, count) in work_units(&sample.work) {
                *distribution
                    .work_unit_totals
                    .entry(format!("{kind}:{unit}"))
                    .or_default() += count;
            }
        }
        self.lifetime_peak_bytes = self.lifetime_peak_bytes.max(peak);
        self.passed += 1;
        Ok(())
    }

    fn report(&self) -> Value {
        let classes = self
            .classes
            .iter()
            .map(|(class, samples)| {
                (
                    class.clone(),
                    json!({
                        "samples": samples.warm_ns.len(),
                        "warm_api_latency_ns": percentiles(&samples.warm_ns),
                        "cold_same_api_latency_ns": percentiles(&samples.cold_api_ns),
                        "cold_supplied_view_latency_ns": percentiles(&samples.cold_view_ns),
                        "sampled_process_resident_bytes": percentiles(&samples.resident_bytes),
                        "disposition_counts": samples.dispositions,
                        "fallback_reason_counts": samples.fallback_reasons,
                        "actual_work_unit_totals": samples.work_unit_totals,
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        json!({
            "comparison_result": "PASS", "successful_comparisons": self.passed,
            "successful_restorations":self.restored,
            "restoration_wall_time_ns":self.restoration_wall_time_ns,
            "post_warm_harness_wall_time_ns":self.post_warm_harness_wall_time_ns,
            "harness_timing_scope":"comparison capture, diagnostics, byte/context comparison, record construction and release, excluding both cold API calls and baseline restoration; final overhead record append is outside this sum",
            "classes": classes, "maximum_observed_lifetime_peak_resident_bytes": self.lifetime_peak_bytes,
            "maximum_comparison_scratch_accounted_bytes":self.maximum_comparison_scratch_bytes,
            "comparison_scratch_limit_bytes":MAX_COMPARISON_SCRATCH_BYTES,
            "comparison_scratch_scope":"full eleven-member byte snapshot, input backing, contexts and bounded client metadata; separate from Session accounting; released before untimed restoration; not a hard RSS bound",
            "percentile_method": "nearest rank, ceil(p*n/100), no interpolation",
            "memory_scope": "OS process RSS sampled after warm API return; peak is cumulative process lifetime including earlier cold references, not a per-operation peak or allocation charge",
            "timing_scope": "warm and cold_same_api start immediately before the identical capture-through-return API call with identical operations; cold_same_api follows preparation eviction; cold_supplied_view separately times evaluate_view_cold on identical immutable bytes; OS caches are not purged; an untimed actual refresh restores preparation after every comparison",
            "limits": "observed curves only; no numerical latency or RSS budget is asserted",
            "execution_context": "no RustSuiteExecution supplied; eleven canonical analysis artifacts; no execution evidence synthesized",
        })
    }
}

fn percentiles(values: &[u64]) -> Value {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let at = |percent: usize| sorted[(sorted.len() * percent).div_ceil(100).saturating_sub(1)];
    json!({"p50": at(50), "p95": at(95), "p99": at(99), "maximum": sorted.last(),
        "count": sorted.len(), "p99_is_empirical_maximum": sorted.len() < 100})
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn file_digest(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("sha256:{:x}", hash.finalize()))
}

struct CollectorCapture {
    bytes: Vec<u8>,
    error: Option<String>,
}

fn read_collector(mut stream: impl Read, charged: &AtomicUsize) -> CollectorCapture {
    let mut capture = CollectorCapture {
        bytes: Vec::new(),
        error: None,
    };
    let mut buffer = [0_u8; 8192];
    loop {
        let count = match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) => {
                capture.error = Some(format!("collector read {:?}: {error}", error.kind()));
                break;
            }
        };
        if charged
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |bytes| {
                bytes
                    .checked_add(count)
                    .filter(|total| *total <= MAX_COLLECTOR_BYTES)
            })
            .is_err()
        {
            capture.error = Some("collector combined output exceeds 1 MiB".into());
            break;
        }
        capture.bytes.extend_from_slice(&buffer[..count]);
    }
    capture
}

struct CollectorJob {
    child: Child,
    readers: [Option<JoinHandle<CollectorCapture>>; 2],
    captures: [Option<CollectorCapture>; 2],
    status: Option<ExitStatus>,
    joined_readers: usize,
}

impl CollectorJob {
    fn new(mut child: Child) -> Self {
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let charged = Arc::new(AtomicUsize::new(0));
        let mut job = Self {
            child,
            readers: [None, None],
            captures: [None, None],
            status: None,
            joined_readers: 0,
        };
        job.attach_reader(0, stdout, Arc::clone(&charged));
        job.attach_reader(1, stderr, charged);
        job
    }

    fn attach_reader<R: Read + Send + 'static>(
        &mut self,
        index: usize,
        stream: Option<R>,
        charged: Arc<AtomicUsize>,
    ) {
        let reader = stream.map_or_else(
            || Err(io::Error::other("collector pipe was not created")),
            |stream| {
                thread::Builder::new()
                    .name(format!("diagnostic-collector-{index}"))
                    .spawn(move || read_collector(stream, &charged))
            },
        );
        match reader {
            Ok(reader) => self.readers[index] = Some(reader),
            Err(error) => {
                self.captures[index] = Some(CollectorCapture {
                    bytes: Vec::new(),
                    error: Some(format!("collector reader start failed: {error}")),
                });
            }
        }
    }

    fn observe(&mut self) -> io::Result<()> {
        let status = if self.status.is_none() {
            self.child.try_wait().map(|status| self.status = status)
        } else {
            Ok(())
        };
        for index in 0..self.readers.len() {
            if self.readers[index]
                .as_ref()
                .is_some_and(JoinHandle::is_finished)
            {
                let reader = self.readers[index].take().expect("finished reader exists");
                self.captures[index] = Some(reader.join().unwrap_or_else(|_| CollectorCapture {
                    bytes: Vec::new(),
                    error: Some("collector reader panicked".into()),
                }));
                self.joined_readers += 1;
            }
        }
        status
    }

    fn capture_error(&self) -> Option<&str> {
        self.captures
            .iter()
            .flatten()
            .find_map(|capture| capture.error.as_deref())
    }

    fn finished(&self) -> bool {
        self.status.is_some() && self.captures.iter().all(Option::is_some)
    }

    fn wait(&mut self) -> Result<()> {
        let started = Instant::now();
        loop {
            self.observe()?;
            if let Some(error) = self.capture_error() {
                return Err(failure(error));
            }
            if self.finished() {
                if self.status.as_ref().is_some_and(ExitStatus::success) {
                    return Ok(());
                }
                return Err(failure("diagnostic collector exited unsuccessfully"));
            }
            if started.elapsed() >= COLLECTOR_TIMEOUT {
                return Err(failure("diagnostic collector exceeded 30 seconds"));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(&mut self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.status.is_none()
            && let Err(error) = self.child.kill()
        {
            errors.push(format!("collector kill failed: {error}"));
        }
        let started = Instant::now();
        while !self.finished() && started.elapsed() < COLLECTOR_REAP_TIMEOUT {
            if let Err(error) = self.observe() {
                let detail = format!("collector reap observation failed: {error}");
                if !errors.contains(&detail) {
                    errors.push(detail);
                }
            }
            if !self.finished() {
                thread::sleep(Duration::from_millis(10));
            }
        }
        if !self.finished() {
            errors.push("collector child or inherited output pipe remains unresolved".into());
        }
        errors
    }

    fn diagnostics(&self) -> Value {
        let output = self
            .captures
            .iter()
            .map(|capture| {
                capture.as_ref().map(|capture| {
                    json!({"captured_bytes":capture.bytes.len(),"digest":digest(&capture.bytes),
                        "text":String::from_utf8_lossy(&capture.bytes),"capture_error":capture.error})
                })
            })
            .collect::<Vec<_>>();
        json!({"pid":self.child.id(),"direct_child_reaped":self.status.is_some(),
            "exit_status":self.status.as_ref().map(ToString::to_string),
            "joined_pipe_readers":self.joined_readers,
            "stdout_and_stderr":output,
            "absence_proof_scope":"owned Child::try_wait exit status and finished pipe-reader joins; descendant absence is not inferred"})
    }
}

fn captured_collector(
    program: &str,
    arguments: &[String],
    retention: &mut Retention,
) -> Result<Vec<u8>> {
    retention.collector_sequence += 1;
    let name = format!("collector-{:04}", retention.collector_sequence);
    let request = json!({"program":program,"arguments":arguments,
        "originating_phase":retention.last_phase,"timeout_ms":COLLECTOR_TIMEOUT.as_millis(),
        "reap_timeout_ms":COLLECTOR_REAP_TIMEOUT.as_millis(),
        "combined_output_byte_limit":MAX_COLLECTOR_BYTES});
    retention.document(&format!("{name}-request.json"), &request)?;
    let child = match Command::new(program)
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            let record = json!({"request":request,"result":"FAIL","spawn_error":error.to_string(),
                "child_created":false,"descendants_uncertain":false});
            retention.collector_failures.push(record.clone());
            if let Err(record_error) = retention.document(&format!("{name}-result.json"), &record) {
                eprintln!("could not retain collector spawn error: {record_error}");
            }
            return Err(error.into());
        }
    };
    let mut job = CollectorJob::new(child);
    let started = retention.document(
        &format!("{name}-start.json"),
        &json!({"request":request,"pid":job.child.id(),"owned_native_child_handle":true,
            "lifetime":"started; no exit or descendant absence claimed",
            "recovery":"PID alone does not authorize termination or cleanup"}),
    );
    if let Err(error) = &started {
        eprintln!(
            "could not retain collector start for owned PID {}: {error}",
            job.child.id()
        );
    }
    let result = started.and_then(|()| job.wait());
    let cleanup_errors = if result.is_err() {
        job.stop()
    } else {
        Vec::new()
    };
    let record = json!({"request":request,"result":if result.is_ok(){"PASS"}else{"FAIL"},
        "originating_error":result.as_ref().err().map(ToString::to_string),
        "cleanup_errors":cleanup_errors,"lifetime":job.diagnostics(),
        "descendant_absence_proven":false,
        "descendants_uncertain":result.is_err(),
        "recovery":"on collector failure, benchmark ends; Session storage cleanup does not establish collector descendant absence"});
    if result.is_err() {
        retention.collector_failures.push(record.clone());
    }
    let recorded = retention.document(&format!("{name}-result.json"), &record);
    if !job.finished() {
        retention.unresolved_collectors.push(job);
        if let Err(record_error) = recorded {
            eprintln!("could not retain unresolved collector: {record_error}");
        }
        return match result {
            Err(error) => Err(error),
            Ok(()) => Err(failure("collector lifetime remains unresolved")),
        };
    }
    if let Err(error) = result {
        if let Err(record_error) = recorded {
            eprintln!("could not retain collector failure: {record_error}");
        }
        return Err(error);
    }
    recorded?;
    Ok(job.captures[0]
        .take()
        .expect("completed stdout capture")
        .bytes)
}

fn command_text(program: &str, arguments: &[&str], retention: &mut Retention) -> Result<String> {
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect::<Vec<_>>();
    Ok(
        String::from_utf8(captured_collector(program, &arguments, retention)?)?
            .trim()
            .to_owned(),
    )
}

fn python_json(source: &str, arguments: &[String], retention: &mut Retention) -> Result<Value> {
    let mut selected = vec!["-B".into(), "-c".into(), source.into()];
    selected.extend_from_slice(arguments);
    let output = captured_collector(
        if cfg!(windows) { "python" } else { "python3" },
        &selected,
        retention,
    )?;
    Ok(serde_json::from_slice(&output)?)
}

fn process_memory(retention: &mut Retention) -> Result<Value> {
    if cfg!(windows) {
        python_json(
            r"
import ctypes, ctypes.wintypes as w, json, sys
class Counters(ctypes.Structure):
    _fields_ = [('cb',w.DWORD),('PageFaultCount',w.DWORD),('PeakWorkingSetSize',ctypes.c_size_t),('WorkingSetSize',ctypes.c_size_t),('QuotaPeakPagedPoolUsage',ctypes.c_size_t),('QuotaPagedPoolUsage',ctypes.c_size_t),('QuotaPeakNonPagedPoolUsage',ctypes.c_size_t),('QuotaNonPagedPoolUsage',ctypes.c_size_t),('PagefileUsage',ctypes.c_size_t),('PeakPagefileUsage',ctypes.c_size_t)]
k = ctypes.WinDLL('kernel32', use_last_error=True)
p = ctypes.WinDLL('psapi', use_last_error=True)
k.OpenProcess.argtypes = [w.DWORD,w.BOOL,w.DWORD]
k.OpenProcess.restype = w.HANDLE
k.CloseHandle.argtypes = [w.HANDLE]
p.GetProcessMemoryInfo.argtypes = [w.HANDLE,ctypes.POINTER(Counters),w.DWORD]
handle = k.OpenProcess(0x0400 | 0x0010,False,int(sys.argv[1]))
if not handle: raise ctypes.WinError(ctypes.get_last_error())
try:
    c = Counters(); c.cb = ctypes.sizeof(c)
    if not p.GetProcessMemoryInfo(handle,ctypes.byref(c),c.cb): raise ctypes.WinError(ctypes.get_last_error())
    print(json.dumps({'collector':'Windows GetProcessMemoryInfo','resident_bytes':c.WorkingSetSize,'lifetime_peak_resident_bytes':c.PeakWorkingSetSize}))
finally: k.CloseHandle(handle)
",
            &[std::process::id().to_string()],
            retention,
        )
    } else {
        let status = fs::read_to_string("/proc/self/status")?;
        let read = |name: &str| -> Result<u64> {
            let line = status
                .lines()
                .find(|line| line.starts_with(name))
                .ok_or_else(|| failure(format!("OS RSS counter {name} unavailable")))?;
            let value = line
                .split_whitespace()
                .nth(1)
                .ok_or_else(|| failure("invalid OS RSS counter"))?;
            value
                .parse::<u64>()?
                .checked_mul(1024)
                .ok_or_else(|| failure("OS RSS counter overflow"))
        };
        Ok(
            json!({"collector":"Linux /proc/self/status", "resident_bytes":read("VmRSS:")?,
            "lifetime_peak_resident_bytes":read("VmHWM:")?}),
        )
    }
}

fn hardware(retention: &mut Retention) -> Result<Value> {
    let mut result = python_json(
        r"
import datetime, json, os, platform, sys
print(json.dumps({'machine':platform.node(),'platform':platform.platform(),'processor':platform.processor(),'logical_cpus':os.cpu_count(),'collector_python':sys.executable,'collector_version':sys.version,'observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}))
",
        &[],
        retention,
    )?;
    if cfg!(windows) {
        let source = "$cpu=Get-CimInstance Win32_Processor|Select-Object Name,NumberOfCores,NumberOfLogicalProcessors; $os=Get-CimInstance Win32_OperatingSystem|Select-Object TotalVisibleMemorySize,Version,BuildNumber; @{cpu=$cpu;os=$os}|ConvertTo-Json -Depth 5 -Compress";
        result["native_hardware"] = serde_json::from_str(&command_text(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", source],
            retention,
        )?)?;
    } else {
        result["cpuinfo"] = json!(fs::read_to_string("/proc/cpuinfo")?);
        result["meminfo"] = json!(fs::read_to_string("/proc/meminfo")?);
    }
    Ok(result)
}

fn member_hashes(generation: &Generation) -> BTreeMap<String, String> {
    generation
        .canonical_artifacts()
        .iter()
        .map(|(path, bytes)| (path.clone(), digest(bytes.as_bytes())))
        .collect()
}

fn work_json(work: &SessionWork) -> Value {
    json!({"program":{
        "parsed_files":work.program.parsed_files,"reused_parse_files":work.program.reused_parse_files,
        "rebuilt_declaration_files":work.program.rebuilt_declaration_files,"reused_declaration_files":work.program.reused_declaration_files,
        "analyzed_bodies":work.program.analyzed_bodies,"reused_bodies":work.program.reused_bodies,
        "rebuilt_callers":work.program.rebuilt_callers,"reused_callers":work.program.reused_callers,
        "recomputed_components":work.program.recomputed_components,"reused_components":work.program.reused_components,
        "type_fixed_point_rounds":work.program.type_fixed_point_rounds},
        "semantic":work.semantic,"state_effect":work.state_effect,
        "parser":{"tokenizations":work.tokenizations,"input_bytes_tokenized":work.input_bytes_tokenized,
        "admission_bytes_added":work.parser_admission_bytes_added,"epoch_rotated":work.parser_epoch_rotated,
        "discarded_tokenizations":work.discarded_tokenizations,"discarded_input_bytes":work.discarded_input_bytes,
        "discarded_admission_bytes":work.discarded_parser_bytes,"retained_admission_bytes":work.retained_parser_bytes,
        "retained_input_bytes":work.retained_parser_input_bytes,"retained_tokenizations":work.retained_parser_tokenizations,
        "retained_allocation_charge":work.retained_parser_charge},"prepared_units":work.prepared_units,
        "phase_measurements":work.phase_measurements,
        "preparation_accounting":{"bytes_before_eviction":work.preparation_bytes_before_eviction,
            "units_before_eviction":work.preparation_units_before_eviction,
            "program_bytes":work.preparation_bytes_by_owner[0],
            "domain_bytes":work.preparation_bytes_by_owner[1],
            "effect_bytes":work.preparation_bytes_by_owner[2],
            "scope":"unchanged conservative owner charges; distinct from process RSS and completed generation charges"}})
}

fn work_units(work: &SessionWork) -> [(&'static str, usize); 16] {
    [
        ("parsed_files", work.program.parsed_files),
        ("reused_parse_files", work.program.reused_parse_files),
        ("analyzed_bodies", work.program.analyzed_bodies),
        ("reused_bodies", work.program.reused_bodies),
        ("rebuilt_callers", work.program.rebuilt_callers),
        ("reused_callers", work.program.reused_callers),
        ("recomputed_components", work.program.recomputed_components),
        ("reused_components", work.program.reused_components),
        (
            "type_fixed_point_rounds",
            work.program.type_fixed_point_rounds,
        ),
        ("rebuilt_domain_rounds", work.semantic.rebuilt_domain_rounds),
        ("reused_domain_rounds", work.semantic.reused_domain_rounds),
        (
            "rebuilt_direct_units",
            work.state_effect.rebuilt_direct_units,
        ),
        ("reused_direct_units", work.state_effect.reused_direct_units),
        (
            "rebuilt_closure_rounds",
            work.state_effect.rebuilt_closure_rounds,
        ),
        (
            "reused_closure_rounds",
            work.state_effect.reused_closure_rounds,
        ),
        ("tokenizations", work.tokenizations),
    ]
}

fn options() -> SessionOptions {
    SessionOptions {
        storage_policy: StoragePolicy {
            retain_shared_compiler: false,
            ..StoragePolicy::default()
        },
        ..SessionOptions::default()
    }
}

fn limits_json() -> Value {
    let limits = options().limits;
    json!({"max_source_bytes":limits.max_source_bytes,"max_files":limits.max_files,
        "max_symbols":limits.max_symbols,"max_calls":limits.max_calls,"max_dependencies":limits.max_dependencies,
        "max_generations":limits.max_generations,"max_candidates":limits.max_candidates,
        "max_accounted_bytes":limits.max_accounted_bytes,"max_preparation_bytes":limits.max_preparation_bytes,
        "max_preparation_units":limits.max_preparation_units,"max_parser_bytes":limits.max_parser_bytes})
}

fn cleanup_json(report: &StorageReport) -> Value {
    json!({"disk_free_before":report.disk_free_before,"disk_free_after":report.disk_free_after,
        "cleaned_bytes":report.cleaned_bytes,"retained_bytes":report.retained_bytes,"lifecycle":report.lifecycle})
}

struct Warm {
    generation: Arc<Generation>,
    metrics: WarmMetrics,
}

struct WarmMetrics {
    work: SessionWork,
    disposition: SessionDisposition,
    reasons: Vec<String>,
    elapsed_ns: u64,
    proposal: Value,
}

struct WarmMetricsCharge {
    struct_bytes: usize,
    string_vector_slots: usize,
    string_vector_slot_bytes: usize,
    string_content_bytes: usize,
    string_capacity_bytes: usize,
    proposal_bytes: usize,
    phase_measurement_slot_bytes: usize,
    total: usize,
}

impl WarmMetricsCharge {
    fn for_metrics(metrics: &WarmMetrics) -> Result<Self> {
        let vectors = [
            &metrics.reasons,
            &metrics.work.semantic.fallback_reasons,
            &metrics.work.state_effect.fallback_reasons,
        ];
        let slots = checked_scratch_sum(vectors.iter().map(|values| values.capacity()))?;
        let string_vector_slot_bytes = slots
            .checked_mul(std::mem::size_of::<String>())
            .ok_or_else(|| failure("comparison scalar slot charge overflow"))?;
        let string_capacity_bytes = checked_scratch_sum(
            vectors
                .iter()
                .flat_map(|values| values.iter())
                .map(String::capacity),
        )?;
        let string_content_bytes = checked_scratch_sum(
            vectors
                .iter()
                .flat_map(|values| values.iter())
                .map(String::len),
        )?;
        let struct_bytes = std::mem::size_of::<WarmMetrics>();
        let proposal_bytes = value_allocation_bytes(&metrics.proposal)?;
        let phase_measurement_slot_bytes = metrics
            .work
            .phase_measurements
            .capacity()
            .checked_mul(std::mem::size_of::<
                fortress_core::session::EvaluationPhaseMeasurement,
            >())
            .ok_or_else(|| failure("comparison phase measurement charge overflow"))?;
        // Existing metrics are moved, not cloned. Sixteen extents also admit
        // both cold results and their work/proposal/reason raw-row projections.
        let total = checked_scratch_sum([
            struct_bytes,
            string_vector_slot_bytes,
            string_capacity_bytes,
            proposal_bytes,
            phase_measurement_slot_bytes,
        ])?
        .checked_mul(COMPARISON_METRICS_COPIES)
        .ok_or_else(|| failure("comparison scalar charge overflow"))?
        .max(MIN_COMPARISON_METRICS_BYTES);
        Ok(Self {
            struct_bytes,
            string_vector_slots: slots,
            string_vector_slot_bytes,
            string_content_bytes,
            string_capacity_bytes,
            proposal_bytes,
            phase_measurement_slot_bytes,
            total,
        })
    }

    fn accounting(&self) -> Value {
        json!({"struct_bytes":self.struct_bytes,
            "string_vector_slots":self.string_vector_slots,
            "string_struct_bytes":std::mem::size_of::<String>(),
            "string_vector_slot_bytes":self.string_vector_slot_bytes,
            "string_content_bytes":self.string_content_bytes,
            "string_capacity_bytes":self.string_capacity_bytes,
            "proposal_allocation_charge":self.proposal_bytes,
            "phase_measurement_slot_bytes":self.phase_measurement_slot_bytes,
            "metadata_copies":COMPARISON_METRICS_COPIES,"minimum_admission_bytes":MIN_COMPARISON_METRICS_BYTES,
            "metrics_accounted_bytes":self.total})
    }
}

#[derive(Clone, Copy)]
struct ActiveCase<'a> {
    class: &'a str,
    identity: &'a str,
    root: &'a Path,
    base_subject: Option<&'a Value>,
}

#[derive(Clone, Copy)]
struct CandidateSpec<'a> {
    path: &'a str,
    needle: &'a str,
    replacement: &'a str,
    candidate_id: &'a str,
}

fn elapsed(start: Instant) -> Result<u64> {
    Ok(u64::try_from(start.elapsed().as_nanos())?)
}

fn unchanged(
    session: &mut Session,
    retention: &mut Retention,
    active: &ActiveCase<'_>,
    phase: &str,
) -> Result<Warm> {
    let proposal = json!({"operation":"unchanged"});
    retention.phase(active, phase, &proposal)?;
    let start = Instant::now();
    let update = session.refresh(&SourceDelta::default())?;
    let elapsed_ns = elapsed(start)?;
    Ok(Warm {
        generation: update.generation,
        metrics: WarmMetrics {
            work: update.work,
            disposition: update.disposition,
            reasons: update.reasons,
            elapsed_ns,
            proposal,
        },
    })
}

fn candidate(
    session: &mut Session,
    base: &Generation,
    spec: CandidateSpec<'_>,
    retention: &mut Retention,
    active: &ActiveCase<'_>,
    phase: &str,
) -> Result<Warm> {
    let CandidateSpec {
        path,
        needle,
        replacement,
        candidate_id,
    } = spec;
    retention.phase(
        active,
        "prepare_candidate_operations",
        &json!({"path":path,"needle":needle,"replacement":replacement,
        "candidate_id":candidate_id,"api_phase":phase}),
    )?;
    let bytes = base
        .source_view()
        .bytes(path)
        .ok_or_else(|| failure("candidate path absent"))?;
    let source = std::str::from_utf8(bytes)?;
    if source.matches(needle).count() != 1 {
        return Err(failure(format!(
            "benchmark mutation anchor at {path} is not unique"
        )));
    }
    let candidate_bytes = source.replacen(needle, replacement, 1).into_bytes();
    let proposal = json!({"operation":"replace", "path":path, "preimage_digest":digest(bytes),
        "candidate_digest":digest(&candidate_bytes),"needle":needle,"replacement":replacement});
    let operations = vec![ChangeOperation::Replace {
        path: path.into(),
        base_bytes: bytes.to_vec(),
        candidate_bytes,
    }];
    retention.phase(active, phase, &proposal)?;
    let start = Instant::now();
    let update = session.evaluate_delta(candidate_id, base.input_revision(), operations)?;
    let elapsed_ns = elapsed(start)?;
    Ok(Warm {
        generation: update.generation,
        metrics: WarmMetrics {
            work: update.work,
            disposition: update.disposition,
            reasons: update.reasons,
            elapsed_ns,
            proposal,
        },
    })
}

fn same_api_cold(
    session: &mut Session,
    proposal: &Value,
    retention: &mut Retention,
    active: &ActiveCase<'_>,
) -> Result<Warm> {
    retention.phase(active, "evict_preparation_for_same_api_cold", proposal)?;
    session.evict_preparation()?;
    if proposal["operation"] == "unchanged" {
        return unchanged(session, retention, active, "cold_same_api");
    }
    retention.phase(active, "acquire_actual_base_for_same_api_cold", proposal)?;
    let base = session.acquire_generation()?;
    let field = |name: &str| {
        proposal[name]
            .as_str()
            .ok_or_else(|| failure(format!("missing proposal {name}")))
    };
    candidate(
        session,
        &base,
        CandidateSpec {
            path: field("path")?,
            needle: field("needle")?,
            replacement: field("replacement")?,
            candidate_id: "reference",
        },
        retention,
        active,
        "cold_same_api",
    )
}

struct CapturedWarm {
    snapshot: ComparisonSnapshot,
    metrics: WarmMetrics,
    memory: Value,
    before_release: (usize, usize),
    after_release: (usize, usize),
    scratch_accounting: Value,
    metrics_charge: usize,
    scratch_bytes: usize,
}

fn capture_warm(
    session: &mut Session,
    warm: Warm,
    active: &ActiveCase<'_>,
    retention: &mut Retention,
) -> Result<CapturedWarm> {
    let Warm {
        generation,
        metrics,
    } = warm;
    retention.phase(active, "observe_warm_process_memory", &metrics.proposal)?;
    let memory = process_memory(retention)?;
    let before_release = session.resource_usage()?;
    retention.phase(active, "capture_comparison_snapshot", &metrics.proposal)?;
    let metrics_charge = WarmMetricsCharge::for_metrics(&metrics)?;
    let required = ComparisonSnapshot::required_bytes(&generation)?;
    let total = checked_scratch_sum([required, metrics_charge.total])?;
    if total > MAX_COMPARISON_SCRATCH_BYTES {
        return Err(failure("total comparison scratch exceeds one GiB"));
    }
    let snapshot = ComparisonSnapshot::capture(
        &generation,
        MAX_COMPARISON_SCRATCH_BYTES - metrics_charge.total,
    )?;
    let scratch_accounting = json!({"snapshot":snapshot.accounting(),
        "warm_metrics":metrics_charge.accounting(),"total_accounted_bytes":total,
        "max_accounted_bytes":MAX_COMPARISON_SCRATCH_BYTES,
        "admission":"checked before canonical/context/source cloning",
        "scope":"bounded comparison-client allocations outside the Session model account; not a hard RSS bound"});
    retention.phase(active, "release_warm_generation", &metrics.proposal)?;
    session.release_candidate("measured");
    drop(generation);
    let after_release = session.resource_usage()?;
    retention.phase(
        active,
        "warm_generation_released",
        &json!({
        "accounted_bytes":after_release.0,"charged_generations":after_release.1,
        "comparison_scratch":scratch_accounting}),
    )?;
    Ok(CapturedWarm {
        snapshot,
        metrics,
        memory,
        before_release,
        after_release,
        scratch_accounting,
        metrics_charge: metrics_charge.total,
        scratch_bytes: total,
    })
}

struct ColdComparisons {
    same_view: bool,
    same_api: bool,
    view_ns: u64,
    view_work: Value,
    view_artifacts: BTreeMap<String, String>,
    view_context: Value,
    view_usage: (usize, usize),
    after_view_release: (usize, usize),
    api: Warm,
    api_usage: (usize, usize),
    view_metrics_accounting: Value,
    api_metrics_accounting: Value,
}

fn cold_comparisons(
    session: &mut Session,
    warm: &CapturedWarm,
    active: &ActiveCase<'_>,
    retention: &mut Retention,
) -> Result<ColdComparisons> {
    retention.phase(
        active,
        "cold_supplied_view",
        &json!({"proposal":warm.metrics.proposal,
        "supplied_view_digest":warm.snapshot.source_view().digest()}),
    )?;
    let start = Instant::now();
    let cold_view = session.evaluate_view_cold(warm.snapshot.source_view().clone())?;
    let view_ns = elapsed(start)?;
    require_cold_owner_work(&cold_view.work)?;
    let same_view = warm.snapshot.matches(&cold_view.generation);
    let view_metrics = WarmMetrics {
        work: cold_view.work,
        disposition: cold_view.disposition,
        reasons: cold_view.reasons,
        elapsed_ns: view_ns,
        proposal: Value::Null,
    };
    drop(cold_view.availability_changes);
    let view_charge = WarmMetricsCharge::for_metrics(&view_metrics)?;
    if view_charge.total > warm.metrics_charge {
        return Err(failure(
            "cold view metadata exceeds admitted comparison scratch",
        ));
    }
    let view_work = work_json(&view_metrics.work);
    let view_artifacts = member_hashes(&cold_view.generation);
    let view_context = context(&cold_view.generation);
    let view_usage = session.resource_usage()?;
    drop(cold_view.generation);
    drop(view_metrics);
    let after_view_release = session.resource_usage()?;
    retention.phase(
        active,
        "supplied_view_oracle_released",
        &json!({
        "accounted_bytes":after_view_release.0,"charged_generations":after_view_release.1}),
    )?;
    let api = same_api_cold(session, &warm.metrics.proposal, retention, active)?;
    require_cold_owner_work(&api.metrics.work)?;
    let api_charge = WarmMetricsCharge::for_metrics(&api.metrics)?;
    if api_charge.total > warm.metrics_charge {
        return Err(failure(
            "cold API metadata exceeds admitted comparison scratch",
        ));
    }
    let same_api = warm.snapshot.matches(&api.generation);
    let api_usage = session.resource_usage()?;
    Ok(ColdComparisons {
        same_view,
        same_api,
        view_ns,
        view_work,
        view_artifacts,
        view_context,
        view_usage,
        after_view_release,
        api,
        api_usage,
        view_metrics_accounting: view_charge.accounting(),
        api_metrics_accounting: api_charge.accounting(),
    })
}

fn require_cold_owner_work(work: &SessionWork) -> Result<()> {
    if work.program.reused_bodies != 0
        || work.program.reused_callers != 0
        || work.semantic.reused_domain_rounds != 0
        || work.state_effect.reused_direct_units != 0
        || work.state_effect.reused_closure_rounds != 0
    {
        return Err(failure(
            "independent cold comparison reused owner preparation",
        ));
    }
    Ok(())
}

fn comparison_record(
    active: &ActiveCase<'_>,
    warm: &CapturedWarm,
    cold: &ColdComparisons,
) -> Value {
    json!({"case_id":active.identity,"class":active.class,
        "comparison":if cold.same_view && cold.same_api {"PASS"} else {"FAIL"},
        "warm_api_latency_ns":warm.metrics.elapsed_ns,"cold_same_api_latency_ns":cold.api.metrics.elapsed_ns,"cold_supplied_view_latency_ns":cold.view_ns,
        "process_memory_after_warm":warm.memory,"conservative_accounted_bytes_after_warm":warm.before_release.0,
        "charged_generations_after_warm":warm.before_release.1,"subject":warm.snapshot.context(),
        "proposal":warm.metrics.proposal,"warm_disposition":format!("{:?}",warm.metrics.disposition),"warm_reasons":warm.metrics.reasons,
        "cold_same_api_disposition":format!("{:?}",cold.api.metrics.disposition),"cold_same_api_reasons":cold.api.metrics.reasons,
        "warm_work":work_json(&warm.metrics.work),"cold_same_api_work":work_json(&cold.api.metrics.work),"cold_supplied_view_work":cold.view_work,
        "cold_same_api_subject":context(&cold.api.generation),"cold_supplied_view_subject":cold.view_context,
        "warm_artifact_digests":warm.snapshot.artifact_digests(),"cold_same_api_artifact_digests":member_hashes(&cold.api.generation),
        "cold_supplied_view_artifact_digests":cold.view_artifacts,
        "comparison_scratch":warm.scratch_accounting,
        "cold_comparison_metadata":{"supplied_view":cold.view_metrics_accounting,
            "same_api":cold.api_metrics_accounting},
        "session_resource_lifecycle":{"before_warm_release":warm.before_release,
            "after_warm_release":warm.after_release,"supplied_view_oracle_completed":cold.view_usage,
            "after_supplied_view_release":cold.after_view_release,"same_api_oracle_completed":cold.api_usage}})
}

fn compare(
    session: &mut Session,
    warm: Warm,
    active: &ActiveCase<'_>,
    retention: &mut Retention,
    measurements: &mut Measurements,
) -> Result<()> {
    let harness_started = Instant::now();
    let warm = capture_warm(session, warm, active, retention)?;
    let cold = cold_comparisons(session, &warm, active, retention)?;
    let cold_ns = cold
        .api
        .metrics
        .elapsed_ns
        .checked_add(cold.view_ns)
        .ok_or_else(|| failure("cold timing sum overflow"))?;
    let same = cold.same_view && cold.same_api;
    let mut record = comparison_record(active, &warm, &cold);
    if same {
        measurements.record(
            active.class,
            &warm.metrics,
            &cold.api.metrics,
            cold.view_ns,
            &warm.memory,
        )?;
        measurements.maximum_comparison_scratch_bytes = measurements
            .maximum_comparison_scratch_bytes
            .max(warm.scratch_bytes);
    }
    retention.phase(
        active,
        "release_comparison_snapshot",
        &warm.metrics.proposal,
    )?;
    drop(cold);
    session.release_candidate("reference");
    drop(warm);
    let before_restoration = session.resource_usage()?;
    record["session_resource_lifecycle"]["before_restoration"] = json!(before_restoration);
    retention.phase(
        active,
        "comparison_snapshot_released",
        &json!({
        "accounted_bytes":before_restoration.0,"charged_generations":before_restoration.1}),
    )?;
    retention.append(&record)?;
    drop(record);
    if !same {
        return Err(failure(format!(
            "canonical comparison failed: {}",
            active.identity
        )));
    }
    retention.phase(
        active,
        "restore_actual_preparation",
        &json!({"operation":"unchanged"}),
    )?;
    let restoration_started = Instant::now();
    let restored = session.refresh(&SourceDelta::default())?;
    let restoration_ns = elapsed(restoration_started)?;
    retention.append(
        &json!({"case_id":active.identity,"record_kind":"untimed_actual_preparation_restoration",
        "restoration_wall_time_ns":restoration_ns,
        "disposition":format!("{:?}",restored.disposition),"reasons":restored.reasons,
        "subject":context(&restored.generation),"actual_work":work_json(&restored.work)}),
    )?;
    let harness_ns = elapsed(harness_started)?
        .checked_sub(cold_ns)
        .and_then(|value| value.checked_sub(restoration_ns))
        .ok_or_else(|| failure("comparison timing boundaries are inconsistent"))?;
    measurements.restored += 1;
    measurements.restoration_wall_time_ns = measurements
        .restoration_wall_time_ns
        .checked_add(restoration_ns)
        .ok_or_else(|| failure("restoration timing sum overflow"))?;
    measurements.post_warm_harness_wall_time_ns = measurements
        .post_warm_harness_wall_time_ns
        .checked_add(harness_ns)
        .ok_or_else(|| failure("harness timing sum overflow"))?;
    retention.append(&json!({"case_id":active.identity,
        "record_kind":"post_warm_harness_overhead","wall_time_ns":harness_ns}))?;
    Ok(())
}

fn actual_samples(
    session: &mut Session,
    root: &Path,
    retention: &mut Retention,
    measurements: &mut Measurements,
    sample_count: usize,
) -> Result<()> {
    let setup = ActiveCase {
        class: "actual_repository",
        identity: "initial",
        root,
        base_subject: None,
    };
    retention.phase(&setup, "acquire_initial_generation", &json!({}))?;
    let base = session.acquire_generation()?;
    let initial_subject = context(&base);
    retention.document("actual-subject.json", &initial_subject)?;
    drop(base);
    for ordinal in 0..sample_count {
        let class = if ordinal % 2 == 0 {
            "actual_repository_unchanged"
        } else {
            "actual_repository_body_candidate"
        };
        let identity = format!("actual-{ordinal:04}");
        let active = ActiveCase {
            class,
            identity: &identity,
            root,
            base_subject: Some(&initial_subject),
        };
        let warm = if ordinal % 2 == 0 {
            unchanged(session, retention, &active, "warm_api")?
        } else {
            let replacement = format!("(!value.is_empty() && false /* observed body {ordinal} */)");
            retention.phase(
                &active,
                "acquire_actual_candidate_base",
                &json!({"path":ACTUAL_PATH,
                "needle":ACTUAL_NEEDLE,"replacement":replacement}),
            )?;
            let base = session.acquire_generation()?;
            let warm = candidate(
                session,
                &base,
                CandidateSpec {
                    path: ACTUAL_PATH,
                    needle: ACTUAL_NEEDLE,
                    replacement: &replacement,
                    candidate_id: "measured",
                },
                retention,
                &active,
                "warm_api",
            )?;
            drop(base);
            warm
        };
        compare(session, warm, &active, retention, measurements)?;
        println!(
            "completed actual repository sample {}/{sample_count}",
            ordinal + 1
        );
    }
    retention.phase(&setup, "verify_final_subject", &initial_subject)?;
    let final_base = session.acquire_generation()?;
    if context(&final_base) != initial_subject {
        return Err(failure(
            "actual benchmark subject changed during measurement",
        ));
    }
    drop(final_base);
    Ok(())
}

fn error_json(error: &(dyn Error + 'static)) -> Value {
    if let Some(session) = error.downcast_ref::<SessionError>() {
        json!({"kind":format!("{:?}",session.kind()),"detail":session.detail()})
    } else {
        json!({"kind":"BENCHMARK_ERROR","detail":error.to_string()})
    }
}

fn with_session<F>(
    root: &Path,
    storage: &Path,
    retention: &mut Retention,
    label: &str,
    operation: F,
) -> Result<()>
where
    F: FnOnce(&mut Session, &mut Retention) -> Result<()>,
{
    let active = ActiveCase {
        class: label,
        identity: "lifecycle",
        root,
        base_subject: None,
    };
    retention.phase(
        &active,
        "session_open",
        &json!({"storage_root":storage,"limits":limits_json()}),
    )?;
    let mut session = match Session::open(root, storage, options()) {
        Ok(session) => session,
        Err(error) => {
            let recorded = retention.document(&format!("{label}-cleanup.json"), &json!({
                "repository_root":root,"storage_root":storage,"operation_error":error_json(&error),
                "cleanup":"no coordinator returned; production failed-open Drop owns cleanup; no close result claimed",
                "diagnostic_collectors":retention.collector_summary()}));
            if let Err(record_error) = recorded {
                eprintln!("could not retain failed-open cleanup: {record_error}");
            }
            return Err(error.into());
        }
    };
    let cancellation_path = retention.root.join("cancel.request");
    let control = session.control();
    session.set_progress_observer(move |_| {
        // A pending request wins the existing cancellation/publication boundary
        // after an in-flight owner computation returns. No process is killed and
        // no completed raw record, physical input or historical journal is erased.
        if !matches!(fs::symlink_metadata(&cancellation_path),
            Err(error) if error.kind() == io::ErrorKind::NotFound)
        {
            control.cancel();
        }
    });
    let result = operation(&mut session, retention);
    let originating_phase = retention.last_phase.clone();
    let usage = session.resource_usage().map_or_else(
        |error| error_json(&error),
        |usage| json!({"accounted_bytes":usage.0,"generations":usage.1}),
    );
    let close_phase = retention.phase(
        &active,
        "session_close",
        &json!({"storage_root":storage,
        "operation_error":result.as_ref().err().map(|error|error_json(error.as_ref()))}),
    );
    let closed = session.close();
    let recorded = retention.document(&format!("{label}-cleanup.json"), &json!({
        "repository_root":root,"storage_root":storage,"usage_before_close":usage,
        "originating_operation_phase":originating_phase,
        "operation_error":result.as_ref().err().map(|error|error_json(error.as_ref())),
        "storage":closed.as_ref().ok().map(cleanup_json),"close_error":closed.as_ref().err().map(|error|error_json(error)),
        "storage_scope":"Session runtime staging only; diagnostic collector lifetime is recorded separately",
        "diagnostic_collectors":retention.collector_summary(),
        "close_phase_retention_error":close_phase.as_ref().err().map(ToString::to_string)}));
    if let Err(error) = result {
        if let Err(record_error) = recorded {
            eprintln!("could not retain cleanup: {record_error}");
        }
        if let Err(close_error) = closed {
            eprintln!("cleanup also failed: {close_error}");
        }
        return Err(error);
    }
    closed?;
    recorded?;
    close_phase?;
    Ok(())
}

fn actual_repository(
    root: &Path,
    retention: &mut Retention,
    measurements: &mut Measurements,
    campaign: Campaign,
) -> Result<()> {
    let storage = std::env::temp_dir().join("fortress-ops");
    with_session(root, &storage, retention, "actual", |session, retention| {
        actual_samples(
            session,
            root,
            retention,
            measurements,
            campaign.actual_samples(),
        )
    })
}

struct Fixture {
    root: PathBuf,
    storage: PathBuf,
    owner: PathBuf,
}

impl Fixture {
    fn new(run: &Path, count: usize, graph: bool) -> Result<Self> {
        let kind = if graph { "graph" } else { "independent" };
        let owner = run.join(format!("fixture-{kind}-{count}"));
        fs::create_dir(&owner)?;
        let root = owner.join("repository");
        let storage = std::env::temp_dir().join("fortress-ops");
        fs::create_dir_all(root.join("src"))?;
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"measured_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )?;
        let mut library = String::new();
        for group in 0..count.div_ceil(GROUP_SIZE) {
            writeln!(library, "pub mod unit_{group:03};")?;
            let mut source = String::new();
            for ordinal in group * GROUP_SIZE..((group + 1) * GROUP_SIZE).min(count) {
                if graph {
                    let next = group * GROUP_SIZE + (ordinal + 1) % GROUP_SIZE;
                    writeln!(source, "pub fn f{ordinal:04}() {{ f{next:04}(); }}")?;
                } else {
                    writeln!(source, "pub fn f{ordinal:04}() -> u32 {{ 1 }}")?;
                }
            }
            fs::write(root.join(format!("src/unit_{group:03}.rs")), source)?;
        }
        fs::write(root.join("src/lib.rs"), library)?;
        let proposal = discover_repository_bootstrap(
            &root,
            &BootstrapDiscoveryOptions::new(
                Some("PF-MEASURED-FIXTURE".into()),
                Some("Measured Fixture".into()),
            ),
        )?;
        apply_repository_bootstrap(&root, &proposal, false)?;
        Ok(Self {
            root,
            storage,
            owner,
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.root.parent() == Some(self.owner.as_path()) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn fixture_workloads(
    retention: &mut Retention,
    measurements: &mut Measurements,
    graph: bool,
    campaign: Campaign,
) -> Result<()> {
    let kind = if graph { "graph" } else { "independent" };
    for (count, full_samples) in FIXTURE_SIZES {
        let samples = campaign.fixture_samples(full_samples);
        let label = format!("fixture-{kind}-{count}");
        let expected_root = retention.root.join(&label).join("repository");
        retention.phase(
            &ActiveCase {
                class: &label,
                identity: "setup",
                root: &expected_root,
                base_subject: None,
            },
            "create_governed_fixture",
            &json!({"functions":count,"samples":samples,"graph":graph}),
        )?;
        let fixture = Fixture::new(&retention.root, count, graph)?;
        with_session(
            &fixture.root,
            &fixture.storage,
            retention,
            &label,
            |session, retention| {
                fixture_samples(
                    session,
                    &fixture,
                    (count, samples),
                    graph,
                    retention,
                    measurements,
                )
            },
        )?;
        println!("completed {samples} {kind} fixture samples with {count} functions");
    }
    Ok(())
}

fn fixture_samples(
    session: &mut Session,
    fixture: &Fixture,
    population: (usize, usize),
    graph: bool,
    retention: &mut Retention,
    measurements: &mut Measurements,
) -> Result<()> {
    let (count, samples) = population;
    let kind = if graph { "graph" } else { "independent" };
    let setup = ActiveCase {
        class: kind,
        identity: "initial",
        root: &fixture.root,
        base_subject: None,
    };
    retention.phase(&setup, "acquire_initial_generation", &json!({}))?;
    let base = session.acquire_generation()?;
    let initial_subject = context(&base);
    retention.document(&format!("fixture-{kind}-{count}-subject.json"), &json!({
            "subject":initial_subject,"generator":{"kind":kind,"function_count":count,"group_size":GROUP_SIZE},
            "samples":samples,"expected_scope":"isolated first ordinary function body; disposition and actual owner work are observed, never prescribed"}))?;
    drop(base);
    for ordinal in 0..samples {
        let class = format!("fixture_{kind}_{count}");
        let identity = format!("fixture-{kind}-{count}-{ordinal:04}");
        let active = ActiveCase {
            class: &class,
            identity: &identity,
            root: &fixture.root,
            base_subject: Some(&initial_subject),
        };
        let (needle, replacement) = if graph {
            (
                "{ f0001(); }",
                format!("{{ let _ = std::fs::read(\"measured-{ordinal}\"); }}"),
            )
        } else {
            (
                "f0000() -> u32 { 1 }",
                format!("f0000() -> u32 {{ {} }}", ordinal + 2),
            )
        };
        retention.phase(
            &active,
            "acquire_actual_candidate_base",
            &json!({"path":"src/unit_000.rs",
                "needle":needle,"replacement":replacement}),
        )?;
        let base = session.acquire_generation()?;
        let warm = candidate(
            session,
            &base,
            CandidateSpec {
                path: "src/unit_000.rs",
                needle,
                replacement: &replacement,
                candidate_id: "measured",
            },
            retention,
            &active,
            "warm_api",
        )?;
        drop(base);
        compare(session, warm, &active, retention, measurements)?;
    }
    retention.phase(&setup, "verify_final_subject", &initial_subject)?;
    let final_base = session.acquire_generation()?;
    if context(&final_base) != initial_subject {
        return Err(failure("fixture subject changed during measurement"));
    }
    Ok(())
}

fn run(retention: &mut Retention, campaign: Campaign) -> Result<()> {
    let root = std::env::current_dir()?.canonicalize()?;
    retention.phase(
        &ActiveCase {
            class: "benchmark",
            identity: "setup",
            root: &root,
            base_subject: None,
        },
        "collect_run_provenance",
        &json!({}),
    )?;
    if !root.join(".git").is_dir()
        || !root.join(ACTUAL_PATH).is_file()
        || !root.join("_data/Cargo.toml").is_file()
    {
        return Err(failure(
            "run the prebuilt resident benchmark from the actual repository root",
        ));
    }
    let executable = std::env::current_exe()?;
    let hardware = hardware(retention)?;
    let observed_toolchain = command_text("rustc", &["-vV"], retention)?;
    let observed_git_head = command_text("git", &["rev-parse", "HEAD"], retention)?;
    let observed_git_status = command_text("git", &["status", "--porcelain"], retention)?;
    retention.document("provenance.json", &json!({
        "format":"resident-api-empirical-comparison-v1", "hardware":hardware,
        "executable_path":executable,"executable_digest":file_digest(&executable)?,
        "observed_toolchain":observed_toolchain,
        "observed_git_head":observed_git_head,
        "observed_git_status":observed_git_status,
        "limits":limits_json(),"actual_repository_samples":campaign.actual_samples(),
        "campaign":campaign.name(),"authoritative_certification":false,
        "required_full_benchmark_comparisons":300,
        "fixture_sizes_and_samples":FIXTURE_SIZES,
        "storage_scope":"external immutable raw records, unique run, maximum 128 MiB; runtime staging cleaned through StorageReport; records are not application source or a certification artifact",
        "scheduling":"driver must freeze source and run this prebuilt executable with no compiler or issuer; admission remains enabled",
        "cancellation":{"request_file":retention.root.join("cancel.request"),
            "exact_request":"fortress-resident-benchmark-cancel-v1\n",
            "scope":"cooperative phase/publication boundaries; an in-flight owner computation finishes before cancellation; completed evidence is preserved and the campaign remains incomplete; no prefix resume is qualified"},
    }))?;
    let mut measurements = Measurements::default();
    if campaign.actual_samples() > 0 {
        actual_repository(&root, retention, &mut measurements, campaign)?;
    }
    fixture_workloads(retention, &mut measurements, false, campaign)?;
    fixture_workloads(retention, &mut measurements, true, campaign)?;
    if measurements.passed != campaign.expected_comparisons()
        || measurements.restored != campaign.expected_comparisons()
    {
        return Err(failure(
            "campaign comparison/restoration population mismatch",
        ));
    }
    if !matches!(campaign, Campaign::Full) {
        // A development probe that silently became all-cold cannot validate the
        // intended reuse path. Required cold fallback is checked at both ports.
        for (count, _) in FIXTURE_SIZES {
            let class = format!("fixture_independent_{count}");
            let samples = measurements
                .classes
                .get(&class)
                .ok_or_else(|| failure("missing independent development fixture"))?;
            for unit in [
                "warm:reused_bodies",
                "warm:reused_domain_rounds",
                "warm:reused_direct_units",
            ] {
                if samples.work_unit_totals.get(unit).copied().unwrap_or(0) == 0 {
                    return Err(failure(format!(
                        "development fixture {count} did not exercise {unit}"
                    )));
                }
            }
        }
    }
    let final_memory = process_memory(retention)?;
    measurements.lifetime_peak_bytes = measurements.lifetime_peak_bytes.max(
        final_memory["lifetime_peak_resident_bytes"]
            .as_u64()
            .ok_or_else(|| failure("missing final process peak"))?,
    );
    retention.raw.sync_all()?;
    retention.events.sync_all()?;
    retention.check_cancellation()?;
    let mut report = measurements.report();
    report["campaign"] = json!(campaign.name());
    report["authoritative_certification"] = json!(false);
    report["required_full_benchmark_comparisons"] = json!(300);
    report["full_benchmark_population_completed"] = json!(matches!(campaign, Campaign::Full));
    if !matches!(campaign, Campaign::Full) {
        report["comparison_result"] = json!("DEVELOPMENT_PROBE_PASS");
    }
    report["run_wall_time_ns_before_summary_write"] = json!(elapsed(retention.started)?);
    report["raw_records_digest"] = json!(file_digest(&retention.root.join("samples.jsonl"))?);
    report["phase_events_digest"] = json!(file_digest(&retention.root.join("events.jsonl"))?);
    report["final_process_memory"] = final_memory;
    report["diagnostic_collectors"] = retention.collector_summary();
    retention.document("report.json", &report)?;
    Ok(())
}

fn main() -> Result<()> {
    let started = Instant::now();
    let campaign = Campaign::parse()?;
    let mut retention = Retention::new(started)?;
    println!("retained benchmark directory: {}", retention.root.display());
    if let Err(error) = run(&mut retention, campaign) {
        if let Err(record_error) = retention.document(
            "failure.json",
            &json!({"result":"FAIL","error":error_json(error.as_ref()),"last_phase":retention.last_phase,
                "qualification_status":"INCOMPLETE_NO_PASS","authoritative_certification":false,
                "completed_evidence_preserved":true,"prefix_resume_qualified":false,
                "diagnostic_collectors":retention.collector_summary()}),
        ) { eprintln!("could not retain originating failure: {record_error}"); }
        return Err(error);
    }
    println!(
        "retained complete report: {}",
        retention.root.join("report.json").display()
    );
    Ok(())
}
