//! Host interpreter admission and bounded supervision for the embedded consumer.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fortress_core::portable::{PortableError, failure};

const OUTPUT_BYTES: u64 = 1024 * 1024;
const READY_BYTES: usize = 4096;
const DEADLINE: Duration = Duration::from_mins(3);

pub(super) fn interpreter(bundle: &Path) -> Result<PathBuf, PortableError> {
    let cwd = std::env::current_dir()
        .map_err(|error| unavailable(&error))?
        .canonicalize()
        .map_err(|error| unavailable(&error))?;
    let bundle = bundle.canonicalize().map_err(|error| unavailable(&error))?;
    let forbidden = if bundle.is_dir() {
        bundle.as_path()
    } else {
        bundle
            .parent()
            .ok_or_else(|| failure("VERIFIER_UNAVAILABLE", "bundle has no parent"))?
    };
    let explicit = std::env::var_os("FORTRESS_VERIFIER_PYTHON");
    let candidates: Vec<PathBuf> = if let Some(value) = explicit.as_ref() {
        vec![PathBuf::from(value)]
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .filter(|path| path.is_absolute())
            .map(|path| {
                path.join(if cfg!(windows) {
                    "python.exe"
                } else {
                    "python3"
                })
            })
            .collect()
    };
    for candidate in candidates {
        if !candidate.is_absolute() {
            continue;
        }
        let Ok(actual) = candidate.canonicalize() else {
            continue;
        };
        if !outside_inputs(&actual, &[&cwd, forbidden])? || !actual.is_file() {
            continue;
        }
        #[cfg(windows)]
        if !actual
            .extension()
            .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
        {
            continue;
        }
        return Ok(actual);
    }
    Err(failure(
        "VERIFIER_UNAVAILABLE",
        "no absolute host Python outside the working and bundle trees; configure FORTRESS_VERIFIER_PYTHON in the trusted host environment",
    ))
}

pub(crate) fn outside_inputs(tool: &Path, roots: &[&Path]) -> Result<bool, PortableError> {
    use fortress_core::heavy_admission::DirectoryIdentity;
    let identities = roots
        .iter()
        .map(|root| DirectoryIdentity::capture(root))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| unavailable(&error))?;
    for ancestor in tool.ancestors().skip(1) {
        for root in &identities {
            if root
                .matches(ancestor)
                .map_err(|error| unavailable(&error))?
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn unavailable(error: &std::io::Error) -> PortableError {
    failure("VERIFIER_UNAVAILABLE", error.to_string())
}

fn tool_stamp(path: &Path) -> Result<(File, String), PortableError> {
    use fortress_core::observation::physical;
    const MAXIMUM: u64 = 256 * 1024 * 1024;
    if !path.is_absolute() {
        return Err(failure(
            "VERIFIER_UNAVAILABLE",
            "interpreter must be absolute",
        ));
    }
    let mut handle = physical::open_regular(path).map_err(|error| unavailable(&error))?;
    let before = handle.metadata().map_err(|error| unavailable(&error))?;
    if before.len() > MAXIMUM {
        return Err(failure(
            "RESOURCE_LIMIT",
            "interpreter identity budget exceeded",
        ));
    }
    let (bytes, stamp) =
        fortress_core::portable::digest_reader(&mut Read::by_ref(&mut handle).take(MAXIMUM + 1))
            .map_err(|error| unavailable(&error))?;
    if bytes > MAXIMUM || bytes != before.len() {
        return Err(failure(
            "RESOURCE_LIMIT",
            "interpreter grew beyond identity budget",
        ));
    }
    physical::verify_regular(path, &handle, &before).map_err(|error| unavailable(&error))?;
    Ok((handle, stamp))
}

pub(crate) fn require_external_asset(path: &Path, project: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("COLLECTOR_TRUST_REQUIRED: absolute host path required".into());
    }
    let actual = path.canonicalize().map_err(|error| error.to_string())?;
    if !outside_inputs(&actual, &[project]).map_err(|error| error.to_string())? {
        return Err("COLLECTOR_TRUST_REQUIRED: asset belongs to the project".into());
    }
    for ancestor in path.ancestors() {
        let metadata = ancestor
            .symlink_metadata()
            .map_err(|error| error.to_string())?;
        if fortress_core::observation::physical::linked(&metadata) {
            return Err("COLLECTOR_TRUST_REQUIRED: linked host asset".into());
        }
    }
    Ok(())
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(super) fn run(command: Command, script: &'static str) -> Result<(Vec<u8>, u8), PortableError> {
    run_bounded(command, script, DEADLINE)
}

pub(super) fn run_bounded(
    command: Command,
    script: &'static str,
    deadline: Duration,
) -> Result<(Vec<u8>, u8), PortableError> {
    run_checked(command, script.as_bytes().to_vec(), deadline, None, None)
}

pub(crate) fn run_pinned(
    command: Command,
    deadline: Duration,
    executable_ref: &str,
) -> Result<(Vec<u8>, u8), PortableError> {
    run_pinned_input(command, Vec::new(), deadline, executable_ref)
}

pub(crate) fn run_pinned_input(
    command: Command,
    input: Vec<u8>,
    deadline: Duration,
    executable_ref: &str,
) -> Result<(Vec<u8>, u8), PortableError> {
    run_checked(command, input, deadline, Some(executable_ref), None)
}

pub(crate) fn run_pinned_input_after_ready(
    command: Command,
    input: Vec<u8>,
    deadline: Duration,
    executable_ref: &str,
    ready_line: Vec<u8>,
) -> Result<(Vec<u8>, u8), PortableError> {
    if ready_line.len() > READY_BYTES
        || !ready_line.is_ascii()
        || !ready_line
            .strip_suffix(b"\n")
            .is_some_and(|body| !body.is_empty() && !body.contains(&b'\n'))
    {
        return Err(failure(
            "VERIFIER_UNAVAILABLE",
            "invalid worker readiness premise",
        ));
    }
    run_checked(
        command,
        input,
        deadline,
        Some(executable_ref),
        Some(ready_line),
    )
}

fn run_checked(
    mut command: Command,
    input: Vec<u8>,
    deadline: Duration,
    executable_ref: Option<&str>,
    ready_line: Option<Vec<u8>>,
) -> Result<(Vec<u8>, u8), PortableError> {
    let executable = PathBuf::from(command.get_program());
    let (tool, stamp) = tool_stamp(&executable)?;
    if executable_ref.is_some_and(|reference| reference != stamp) {
        return Err(failure(
            "VERIFIER_UNAVAILABLE",
            "configured executable differs from its trusted identity",
        ));
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = OwnedChild(command.spawn().map_err(|error| unavailable(&error))?);
    let receive = transfer_pipes(&mut child.0, input, ready_line)?;
    let (mut output, mut errors, mut completed) = (Vec::new(), Vec::new(), 0);
    loop {
        while let Ok((id, result)) = receive.try_recv() {
            let bytes = result.map_err(|error| unavailable(&error))?;
            if bytes.len() as u64 > OUTPUT_BYTES {
                return Err(failure("RESOURCE_LIMIT", "verifier output budget exceeded"));
            }
            if id == 1 {
                output = bytes;
            } else if id == 2 {
                errors = bytes;
            }
            completed += 1;
        }
        if completed == 3
            && let Some(status) = child.0.try_wait().map_err(|error| unavailable(&error))?
        {
            let (actual_tool, actual_stamp) = tool_stamp(&executable)?;
            if stamp != actual_stamp
                || !fortress_core::observation::physical::same_file(&tool, &actual_tool)
                    .map_err(|error| unavailable(&error))?
            {
                return Err(failure(
                    "VERIFIER_FAILURE",
                    "host interpreter changed during verification",
                ));
            }
            if output.is_empty() {
                return Err(failure(
                    "VERIFIER_FAILURE",
                    String::from_utf8_lossy(&errors)
                        .chars()
                        .take(1024)
                        .collect::<String>(),
                ));
            }
            return Ok((
                output,
                u8::try_from(status.code().unwrap_or(2)).unwrap_or(2),
            ));
        }
        if started.elapsed() >= deadline {
            return Err(failure(
                "RESOURCE_LIMIT",
                "verifier execution deadline exceeded",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

type PipeResult = (u8, io::Result<Vec<u8>>);

fn transfer_pipes(
    child: &mut Child,
    input: Vec<u8>,
    ready_line: Option<Vec<u8>>,
) -> Result<mpsc::Receiver<PipeResult>, PortableError> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| failure("VERIFIER_UNAVAILABLE", "missing stdin"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| failure("VERIFIER_UNAVAILABLE", "missing stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| failure("VERIFIER_UNAVAILABLE", "missing stderr"))?;
    let (send, receive) = mpsc::channel();
    let (allow_input, wait_for_readiness) = mpsc::sync_channel(1);
    let gated = ready_line.is_some();

    let writer = send.clone();
    std::thread::spawn(move || {
        let result = if gated && wait_for_readiness.recv().is_err() {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "worker readiness was not accepted",
            ))
        } else {
            stdin.write_all(&input)
        };
        let _ = writer.send((0, result.map(|()| Vec::new())));
    });

    let reader = send.clone();
    std::thread::spawn(move || {
        let result = (|| {
            if let Some(expected) = ready_line {
                let mut announced = vec![0; expected.len()];
                stdout.read_exact(&mut announced)?;
                if announced != expected {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "worker readiness differs from its exact premise",
                    ));
                }
                // Only the exact startup frame admits release of the request.
                let _ = allow_input.send(());
            }
            read_pipe(stdout)
        })();
        let _ = reader.send((1, result));
    });
    std::thread::spawn(move || {
        let _ = send.send((2, read_pipe(stderr)));
    });
    Ok(receive)
}

fn read_pipe(pipe: impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.take(OUTPUT_BYTES + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}
