//! Read-only invocation of an exactly selected Go workspace editor.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fortress_core::go_workspace_observation::{GoWorkspaceReaderReply, observe_go_workspace};
use fortress_core::heavy_admission::DirectoryIdentity;
use fortress_core::observation::physical;
use fortress_core::portable::{canonical, digest, digest_reader};
use fortress_core::wire::readable_text;

const USAGE: &str = "usage: fortress source-artifacts --observe-go-workspace PROJECT GO_WORK_PATH GO_EXECUTABLE GO_SHA256 TRUSTED_SCRATCH_DIRECTORY";
const TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn run<O: Write, E: Write>(
    arguments: &[String],
    output: &mut O,
    error: &mut E,
) -> io::Result<u8> {
    let [project, manifest, go, executable_ref, scratch] = arguments else {
        writeln!(error, "{USAGE}")?;
        return Ok(super::EXIT_USAGE);
    };
    let project = Path::new(project);
    let go = Path::new(go);
    let scratch = Path::new(scratch);
    let result = observe_go_workspace(project, manifest, |bytes| {
        read_workspace(project, go, executable_ref, scratch, bytes)
    });
    let observation = match result {
        Ok(observation) => observation,
        Err(failure) => {
            writeln!(
                error,
                "Go workspace observation failed: {}",
                readable_text(&failure.to_string())
            )?;
            return Ok(super::EXIT_USAGE);
        }
    };
    let report = serde_json::to_value(observation).map_err(io::Error::other)?;
    let bytes = canonical(&report).map_err(io::Error::other)?;
    super::write_projection(None, output, &bytes)?;
    Ok(super::EXIT_SUCCESS)
}

fn read_workspace(
    project: &Path,
    go: &Path,
    executable_ref: &str,
    scratch: &Path,
    bytes: &[u8],
) -> GoWorkspaceReaderReply {
    let read = || -> Result<GoWorkspaceReaderReply, String> {
        super::verifier_process::require_external_asset(go, project)?;
        if !scratch.is_absolute() {
            return Err("trusted scratch directory must be absolute".into());
        }
        let staged =
            StagedWorkFile::create(project, scratch, bytes).map_err(|error| error.to_string())?;
        let run = |args: &[&str]| {
            staged.revalidate().map_err(|_| {
                fortress_core::portable::failure(
                    "WORKSPACE_INPUT_CHANGED",
                    "workspace staging identity could not be conserved",
                )
            })?;
            let command = editor_command(go, &staged.directory, args);
            super::verifier_process::run_pinned(command, TIMEOUT, executable_ref)
        };
        let (version, status) = run(&["version"]).map_err(|error| error.to_string())?;
        let version = admitted_version(&version, status)
            .ok_or("Go tool version is outside the qualified reader scope")?;
        let json = match run(&["work", "edit", "-json", "go.work"]) {
            Ok((json, 0)) => json,
            Err(error)
                if error.code == "VERIFIER_FAILURE"
                    && error.message.starts_with("go: errors parsing go.work:") =>
            {
                staged.close().map_err(|error| error.to_string())?;
                super::verifier_process::require_external_asset(go, project)?;
                return Ok(GoWorkspaceReaderReply::Invalid);
            }
            _ => return Err("Go workspace JSON unavailable".into()),
        };
        let (formatted, status) =
            run(&["work", "edit", "-print", "go.work"]).map_err(|error| error.to_string())?;
        if status != 0 {
            return Err("Go workspace text unavailable".into());
        }
        staged.close().map_err(|error| error.to_string())?;
        super::verifier_process::require_external_asset(go, project)?;
        Ok(GoWorkspaceReaderReply::Parsed {
            json,
            formatted,
            executable_ref: executable_ref.to_owned(),
            version: version.to_owned(),
        })
    };
    read().unwrap_or(GoWorkspaceReaderReply::Unavailable)
}

fn admitted_version(output: &[u8], status: u8) -> Option<&str> {
    let text = std::str::from_utf8(output).ok()?;
    let mut fields = text.split_ascii_whitespace();
    if status != 0 || fields.next()? != "go" || fields.next()? != "version" {
        return None;
    }
    let version = fields.next()?;
    let target = fields.next()?;
    let current = match std::env::consts::OS {
        "windows" => ("go1.22.12", "windows/amd64"),
        "linux" => ("go1.22.2", "linux/amd64"),
        _ => return None,
    };
    (fields.next().is_none() && (version, target) == current).then_some(version)
}

fn editor_command(go: &Path, directory: &Path, arguments: &[&str]) -> Command {
    let mut command = Command::new(go);
    command
        .env_clear()
        .current_dir(directory)
        .args(arguments)
        .env("GOENV", "off")
        .env("GOWORK", "off")
        .env("GOTOOLCHAIN", "local")
        .env("GOPROXY", "off")
        .env("GOSUMDB", "off")
        .env("GOVCS", "*:off")
        .env("GOCACHE", "off")
        .env("GOMAXPROCS", "1")
        .env("GOMEMLIMIT", "96MiB")
        .env("CGO_ENABLED", "0")
        .env("GOTELEMETRYDIR", directory);
    #[cfg(windows)]
    if let Some(value) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", value);
    }
    command
}

struct StagedWorkFile {
    directory: PathBuf,
    directory_identity: DirectoryIdentity,
    parent: DirectoryIdentity,
    workfile: File,
    metadata: Metadata,
    source_ref: String,
}

impl StagedWorkFile {
    fn create(project: &Path, parent: &Path, bytes: &[u8]) -> io::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let name = format!("fortress-go-work-{}-{timestamp}", std::process::id());
        let (directory, parent_identity) =
            super::projection_command::admit_destination(project, &parent.join(name))?;
        fs::create_dir(&directory)?;
        let directory_identity = DirectoryIdentity::capture(&directory)?;
        if !parent_identity.matches(parent)? {
            return Err(io::Error::other("scratch parent changed"));
        }
        let path = directory.join("go.work");
        let mut workfile = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        workfile.write_all(bytes)?;
        workfile.flush()?;
        let metadata = workfile.metadata()?;
        let stage = Self {
            directory,
            directory_identity,
            parent: parent_identity,
            workfile,
            metadata,
            source_ref: digest(bytes),
        };
        stage.revalidate()?;
        Ok(stage)
    }

    fn revalidate(&self) -> io::Result<()> {
        if !self.parent.matches(
            self.directory
                .parent()
                .ok_or_else(|| io::Error::other("scratch parent missing"))?,
        )? || !self.directory_identity.matches(&self.directory)?
        {
            return Err(io::Error::other("scratch directory changed"));
        }
        let path = self.directory.join("go.work");
        let handle = physical::open_regular(&path)?;
        if !physical::same_file(&handle, &self.workfile)? {
            return Err(io::Error::other("scratch input changed"));
        }
        let (length, reference) = digest_reader(&mut handle.take(self.metadata.len() + 1))?;
        physical::verify_regular(&path, &self.workfile, &self.metadata)?;
        if length != self.metadata.len() || reference != self.source_ref {
            return Err(io::Error::other("scratch input changed"));
        }
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        self.revalidate()?;
        fs::remove_file(self.directory.join("go.work"))?;
        fs::remove_dir(&self.directory)
    }
}

impl Drop for StagedWorkFile {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
