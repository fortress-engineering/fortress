//! Native physical identity and ordinary-file admission; no governance authority.

use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::Path;

/// Whether metadata identifies a link or Windows reparse object.
#[must_use]
pub fn linked(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Opens an ordinary leaf without accepting link or reparse metadata.
/// # Errors
/// Refuses unsupported objects and observable replacement during admission.
pub fn open_regular(path: &Path) -> io::Result<File> {
    let before = fs::symlink_metadata(path)?;
    if linked(&before) || !before.is_file() {
        return Err(io::Error::other("UNSAFE_PATH: expected an ordinary file"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let handle = options.open(path)?;
    let actual = handle.metadata()?;
    if linked(&actual)
        || !actual.is_file()
        || before.len() != actual.len()
        || before.modified()? != actual.modified()?
    {
        return Err(io::Error::other(
            "SOURCE_DRIFT: file changed during admission",
        ));
    }
    Ok(handle)
}

/// Checks retained identity and metadata after reading an ordinary file.
/// # Errors
/// Refuses observable replacement, resizing or modification. This does not lock
/// out hostile host writers or promise an atomic filesystem snapshot.
pub fn verify_regular(path: &Path, handle: &File, before: &Metadata) -> io::Result<()> {
    let current = open_regular(path)?;
    let after = handle.metadata()?;
    let named = current.metadata()?;
    if !same_file(handle, &current)?
        || before.len() != after.len()
        || before.modified()? != after.modified()?
        || after.len() != named.len()
        || after.modified()? != named.modified()?
    {
        return Err(io::Error::other(
            "SOURCE_DRIFT: file changed during observation",
        ));
    }
    Ok(())
}

/// Compares retained native file identities without trusting path spelling.
/// # Errors
/// Refuses platforms without a qualified native identity implementation.
pub fn same_file(left: &File, right: &File) -> io::Result<bool> {
    Ok(native_key(left)? == native_key(right)?)
}

/// Versioned machine-local identity; never a portable semantic subject identity.
/// # Errors
/// Refuses unavailable identities and unsupported operating systems.
pub fn native_key(handle: &File) -> io::Result<String> {
    #[cfg(windows)]
    let (platform, device, index) = {
        let info = winapi_util::file::information(handle)?;
        let (device, index) = (info.volume_serial_number(), info.file_index());
        if device == 0 || index == 0 {
            return Err(io::Error::other("unavailable native object identifier"));
        }
        ("windows", device, index)
    };
    #[cfg(unix)]
    let (platform, device, index) = {
        use std::os::unix::fs::MetadataExt;
        let metadata = handle.metadata()?;
        ("unix", metadata.dev(), metadata.ino())
    };
    #[cfg(any(windows, unix))]
    {
        let material = format!("fortress-physical-directory-v1\0{platform}\0{device}\0{index}");
        Ok(format!("{:x}", Sha256::digest(material.as_bytes())))
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = handle;
        Err(io::Error::other("native identity unavailable"))
    }
}
