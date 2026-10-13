//! Shared operational admission by an open physical directory identity.
//!
//! Adapter journals remain their owners' cleanup authority. This registry
//! only excludes overlapping jobs and retains unresolved owner references.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A retained native directory handle and its operational admission identity.
#[derive(Debug)]
pub struct DirectoryIdentity {
    handle: File,
    key: String,
}

impl DirectoryIdentity {
    fn capture_registry(path: &Path) -> io::Result<Self> {
        let handle = open_registry_directory(path)?;
        if !handle.metadata()?.is_dir() {
            return Err(io::Error::other("admission registry is not a directory"));
        }
        let key = native_key(&handle)?;
        Ok(Self { handle, key })
    }

    /// Opens an existing directory without deriving identity from its spelling.
    ///
    /// # Errors
    /// Returns an error when directory identity cannot be established.
    pub fn capture(path: &Path) -> io::Result<Self> {
        let handle = open_directory(path)?;
        if !handle.metadata()?.is_dir() {
            return Err(io::Error::other("admission subject is not a directory"));
        }
        let key = native_key(&handle)?;
        Ok(Self { handle, key })
    }

    pub(crate) fn pin(path: &Path) -> io::Result<Self> {
        Self::capture_registry(path)
    }

    /// Returns the versioned machine-local admission key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Checks that a path still names this retained physical directory.
    ///
    /// # Errors
    /// Returns an error if either directory's identity cannot be read.
    pub fn matches(&self, path: &Path) -> io::Result<bool> {
        let current = Self::capture(path)?;
        Ok(native_key(&self.handle)? == current.key)
    }
}

#[cfg(windows)]
fn open_directory(path: &Path) -> io::Result<File> {
    open_directory_with_share(path, 7)
}

#[cfg(windows)]
fn open_registry_directory(path: &Path) -> io::Result<File> {
    open_directory_with_share(path, 3)
}

#[cfg(windows)]
fn open_directory_with_share(path: &Path, share_mode: u32) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_READ_ATTRIBUTES (0x80) is sufficient for native identity; generic
    // read would unnecessarily require directory listing access. Sharing is
    // read/write/delete (7) for subjects, or read/write (3) to pin registries.
    OpenOptions::new()
        .access_mode(0x80)
        .share_mode(share_mode)
        // FILE_FLAG_BACKUP_SEMANTICS permits an ordinary directory handle.
        .custom_flags(0x0200_0000)
        .open(path)
}

#[cfg(not(windows))]
fn open_registry_directory(path: &Path) -> io::Result<File> {
    open_directory(path)
}

#[cfg(unix)]
fn open_directory(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(not(any(windows, unix)))]
fn open_directory(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native directory admission is not qualified on this platform",
    ))
}

fn identity_digest(platform: &str, device: u64, index: u64) -> String {
    let material = format!("fortress-physical-directory-v1\0{platform}\0{device}\0{index}");
    format!("{:x}", Sha256::digest(material.as_bytes()))
}

pub(crate) fn same_file(left: &File, right: &File) -> io::Result<bool> {
    Ok(native_key(left)? == native_key(right)?)
}

#[cfg(windows)]
fn native_key(handle: &File) -> io::Result<String> {
    let info = winapi_util::file::information(handle)?;
    let device = info.volume_serial_number();
    let index = info.file_index();
    if device == 0 || index == 0 {
        return Err(io::Error::other("unavailable native directory identifier"));
    }
    Ok(identity_digest("windows", device, index))
}

#[cfg(unix)]
fn native_key(handle: &File) -> io::Result<String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = handle.metadata()?;
    Ok(identity_digest("unix", metadata.dev(), metadata.ino()))
}

#[cfg(not(any(windows, unix)))]
fn native_key(_handle: &File) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native identity unavailable",
    ))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    root_identity: String,
    run_nonce: String,
    journal_path: PathBuf,
    compiler_path: PathBuf,
    completed: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u8,
    native_identity: String,
    registrations: BTreeMap<String, Registration>,
}

/// An exclusive cross-adapter permit, held throughout a heavy operation.
pub struct HeavyAdmissionGuard {
    _lease: File,
    anchor: DirectoryIdentity,
    registry_directory: DirectoryIdentity,
    directory: DirectoryIdentity,
    registry_root: PathBuf,
    registry_path: PathBuf,
    registry: Registry,
    _recovery_pins: Vec<DirectoryIdentity>,
    _recovery_lock: Option<File>,
}

impl HeavyAdmissionGuard {
    /// Excludes another adapter and rejects unresolved prior owner journals.
    ///
    /// # Errors
    /// Returns an error for overlap or uncertain operational state.
    pub fn acquire(directory: DirectoryIdentity) -> io::Result<Self> {
        Self::acquire_inner(directory, None)
    }

    pub(crate) fn acquire_for_recovery(
        directory: DirectoryIdentity,
        namespace: &str,
        root_identity: &str,
    ) -> io::Result<Self> {
        Self::acquire_inner(directory, Some((namespace, root_identity)))
    }

    pub(crate) fn acquire_existing_for_recovery(
        directory: DirectoryIdentity,
        root_identity: &str,
    ) -> io::Result<Self> {
        let mut root = fixed_anchor();
        let mut pins = Vec::new();
        for component in [
            None,
            Some("fortress-ops"),
            Some("admission-v1"),
            Some(directory.key()),
        ] {
            if let Some(component) = component {
                root.push(component);
            }
            let metadata = fs::symlink_metadata(&root)?;
            if linked(&metadata) || !metadata.is_dir() {
                return Err(io::Error::other(
                    "existing admission directory is uncertain",
                ));
            }
            pins.push(DirectoryIdentity::pin(&root)?);
        }
        let lock_path = root.join("heavy.lock");
        check_plain_file(&lock_path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(3);
        }
        let lock = options.open(&lock_path)?;
        let guard = Self::acquire_inner(directory, Some(("rust", root_identity)))?;
        Ok(Self {
            _recovery_pins: pins,
            _recovery_lock: Some(lock),
            ..guard
        })
    }

    fn acquire_inner(
        directory: DirectoryIdentity,
        recovery: Option<(&str, &str)>,
    ) -> io::Result<Self> {
        let fixed = fixed_anchor();
        let anchor = DirectoryIdentity::capture_registry(&fixed)?;
        let canonical_anchor = fixed.canonicalize()?;
        if !anchor.matches(&canonical_anchor)? {
            return Err(io::Error::other("admission anchor identity changed"));
        }
        let mut root = canonical_anchor;
        for component in ["fortress-ops", "admission-v1", directory.key()] {
            root.push(component);
            create_plain_directory(&root)?;
        }
        let registry_directory = DirectoryIdentity::capture_registry(&root)?;
        let lease_path = root.join("heavy.lock");
        check_plain_file(&lease_path)?;
        let mut lease_options = OpenOptions::new();
        lease_options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Never allow an unlink/recreate lease to overlap this handle.
            lease_options.share_mode(3);
        }
        let lease = lease_options.open(&lease_path)?;
        check_plain_file(&lease_path)?;
        if !anchor.matches(&fixed)? || !registry_directory.matches(&root)? {
            return Err(io::Error::other("admission registry directory changed"));
        }
        lease.try_lock().map_err(io::Error::other)?;
        let registry_path = root.join("owners.json");
        check_plain_file(&registry_path)?;
        let registry = if registry_path.exists() {
            let bytes = read_record(&registry_path, 16_384)?;
            crate::wire::parse_strict_json_bytes::<Registry>(&bytes).map_err(io::Error::other)?
        } else {
            Registry {
                version: 1,
                native_identity: directory.key().into(),
                registrations: BTreeMap::new(),
            }
        };
        if registry.version != 1
            || registry.native_identity != directory.key()
            || registry.registrations.len() > 2
        {
            return Err(io::Error::other("invalid admission registry identity"));
        }
        for (namespace, registration) in &registry.registrations {
            validate_registration(namespace, registration)?;
            if !registration.completed
                && !journal_finished(namespace, registration)?
                && recovery != Some((namespace.as_str(), registration.root_identity.as_str()))
            {
                return Err(io::Error::other(
                    "unresolved adapter retains heavy admission",
                ));
            }
        }
        Ok(Self {
            _lease: lease,
            anchor,
            registry_directory,
            directory,
            registry_root: root,
            registry_path,
            registry,
            _recovery_pins: Vec::new(),
            _recovery_lock: None,
        })
    }

    /// Returns the retained physical directory identity.
    #[must_use]
    pub const fn directory(&self) -> &DirectoryIdentity {
        &self.directory
    }

    /// Returns the external fixed-anchor registry used by both adapters.
    #[must_use]
    pub fn registry_root(&self) -> &Path {
        &self.registry_root
    }

    pub(crate) fn register(
        &mut self,
        namespace: &str,
        root_identity: &str,
        run_nonce: &str,
        journal_path: &Path,
        compiler_path: &Path,
    ) -> io::Result<()> {
        self.validate_target(namespace, compiler_path)?;
        let registration = Registration {
            root_identity: root_identity.into(),
            run_nonce: run_nonce.into(),
            journal_path: journal_path.to_path_buf(),
            compiler_path: compiler_path.to_path_buf(),
            completed: false,
        };
        validate_registration(namespace, &registration)?;
        if !journal_path.is_file() {
            return Err(io::Error::other(
                "admission registration requires the owner journal",
            ));
        }
        self.registry
            .registrations
            .insert(namespace.into(), registration);
        self.save()
    }

    pub(crate) fn validate_target(&self, namespace: &str, compiler_path: &Path) -> io::Result<()> {
        self.check_root()?;
        if let Some(previous) = self.registry.registrations.get(namespace)
            && previous.compiler_path != compiler_path
        {
            match fs::symlink_metadata(&previous.compiler_path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
                Ok(_) => {
                    return Err(io::Error::other(
                        "retained adapter target must be explicitly cleaned before relocation",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn validate_retirement(
        &self,
        root_identity: &str,
        run_nonce: &str,
        journal_path: &Path,
        compiler_path: &Path,
    ) -> io::Result<()> {
        self.check_root()?;
        if let Some(entry) = self.registry.registrations.get("rust")
            && (entry.root_identity != root_identity
                || entry.run_nonce != run_nonce
                || entry.journal_path != journal_path
                || entry.compiler_path != compiler_path)
        {
            return Err(io::Error::other(
                "another runtime registration prevents retirement",
            ));
        }
        Ok(())
    }

    fn save(&self) -> io::Result<()> {
        self.check_root()?;
        check_plain_file(&self.registry_path)?;
        let mut bytes = serde_json::to_vec_pretty(&self.registry).map_err(io::Error::other)?;
        bytes.push(b'\n');
        if bytes.len() > 16_384 {
            return Err(io::Error::other("oversized admission registry"));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.registry_path)?;
        file.write_all(&bytes)?;
        file.sync_all()
    }

    pub(crate) fn complete_owned(
        &mut self,
        namespace: &str,
        root_identity: &str,
    ) -> io::Result<()> {
        if let Some(entry) = self.registry.registrations.get(namespace)
            && entry.root_identity == root_identity
            && !entry.completed
            && journal_finished(namespace, entry)?
        {
            self.registry
                .registrations
                .get_mut(namespace)
                .expect("known registration")
                .completed = true;
            self.save()?;
        }
        Ok(())
    }

    pub(crate) fn compiler_bytes(&self, own_target: &Path) -> io::Result<u64> {
        self.check_root()?;
        let mut paths = self
            .registry
            .registrations
            .values()
            .map(|entry| entry.compiler_path.clone())
            .collect::<Vec<_>>();
        paths.push(own_target.to_path_buf());
        paths.sort();
        paths.dedup();
        paths.iter().try_fold(0_u64, |sum, path| {
            sum.checked_add(plain_tree_bytes(path)?)
                .ok_or_else(|| io::Error::other("compiler byte count overflow"))
        })
    }

    fn check_root(&self) -> io::Result<()> {
        let root = self
            .registry_path
            .parent()
            .ok_or_else(|| io::Error::other("missing admission registry root"))?;
        let metadata = fs::symlink_metadata(root)?;
        if linked(&metadata)
            || !metadata.is_dir()
            || !self.anchor.matches(&fixed_anchor())?
            || !self.registry_directory.matches(root)?
        {
            return Err(io::Error::other("admission registry directory changed"));
        }
        Ok(())
    }
}

#[cfg(windows)]
fn fixed_anchor() -> PathBuf {
    // The boot-maintained native namespace resolves the Windows installation,
    // independent of SystemRoot, TEMP, TMP, TMPDIR and drive-letter mappings.
    PathBuf::from(r"\\?\GLOBALROOT\SystemRoot\Temp")
}

#[cfg(unix)]
fn fixed_anchor() -> PathBuf {
    PathBuf::from("/tmp")
}

#[cfg(not(any(windows, unix)))]
fn fixed_anchor() -> PathBuf {
    // Unsupported platforms fail in native directory identity capture before
    // an admission directory or lease can be created.
    PathBuf::new()
}

fn linked(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn create_plain_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    if linked(&metadata) || !metadata.is_dir() {
        return Err(io::Error::other(
            "admission registry component is not an ordinary directory",
        ));
    }
    Ok(())
}

fn check_plain_file(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(metadata) if !linked(&metadata) && metadata.is_file() => Ok(()),
        Ok(_) => Err(io::Error::other("admission record is not an ordinary file")),
    }
}

fn read_record(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    check_plain_file(path)?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(u64::try_from(limit).map_err(io::Error::other)? + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::other("oversized admission record"));
    }
    Ok(bytes)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_registration(namespace: &str, entry: &Registration) -> io::Result<()> {
    if !matches!(namespace, "python" | "rust")
        || !lower_hex(&entry.root_identity, 64)
        || !lower_hex(&entry.run_nonce, 24)
    {
        return Err(io::Error::other("invalid admission registration"));
    }
    let short = &entry.root_identity[..16];
    let expected_suffix = PathBuf::from(namespace)
        .join("x")
        .join(short)
        .join(format!("{}.json", entry.run_nonce));
    if !entry.journal_path.is_absolute() || !entry.journal_path.ends_with(expected_suffix) {
        return Err(io::Error::other("invalid adapter journal path"));
    }
    let storage_root = entry
        .journal_path
        .ancestors()
        .nth(4)
        .ok_or_else(|| io::Error::other("missing adapter storage root"))?;
    if entry.compiler_path != storage_root.join(namespace).join("c").join(short) {
        return Err(io::Error::other("invalid adapter compiler path"));
    }
    Ok(())
}

fn journal_finished(namespace: &str, entry: &Registration) -> io::Result<bool> {
    let bytes = read_record(&entry.journal_path, 1_048_576)?;
    let journal: Value = crate::wire::parse_strict_json_bytes(&bytes).map_err(io::Error::other)?;
    if journal.get("root_identity").and_then(Value::as_str) != Some(&entry.root_identity)
        || journal.get("run_nonce").and_then(Value::as_str) != Some(&entry.run_nonce)
    {
        return Err(io::Error::other("adapter journal binding mismatch"));
    }
    let empty = journal
        .get("child_processes")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty);
    let released = journal.get("lease_state").and_then(Value::as_str) == Some("RELEASED");
    let final_state = matches!(
        journal.get("lifecycle").and_then(Value::as_str),
        Some("CLEANUP_COMPLETE" | "FAILED" | "CANCELLED")
    );
    let cleaned = namespace == "rust"
        || matches!(
            journal.get("cleanup_status").and_then(Value::as_str),
            Some("COMPLETE" | "RECOVERED")
        );
    Ok(empty && released && final_state && cleaned)
}

fn plain_tree_bytes(root: &Path) -> io::Result<u64> {
    let mut pending = vec![root.to_path_buf()];
    let mut total = 0_u64;
    while let Some(path) = pending.pop() {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if linked(&metadata) {
            return Err(io::Error::other("linked compiler storage is uncertain"));
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            total = total
                .checked_add(metadata.len())
                .ok_or_else(|| io::Error::other("compiler byte count overflow"))?;
        } else {
            return Err(io::Error::other("unsupported compiler storage entry"));
        }
    }
    Ok(total)
}
