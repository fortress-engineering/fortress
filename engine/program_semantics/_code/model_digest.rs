//! Per-object canonical digest memo for immutable semantic owner models.

use std::fmt::{self, Debug, Formatter};
use std::io::{self, BufWriter, Write};
use std::sync::OnceLock;

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Per-object operational memo for immutable owner models, never source authority.
///
/// Owners must skip this field in serialization, initialize it only when a new
/// immutable model is finalized, and preserve their existing pretty-JSON/LF
/// framing. Cold model construction always starts with an empty memo. No global
/// cache or cross-model lookup exists; failed serialization is never cached.
#[derive(Clone, Default)]
pub(crate) struct ModelDigestMemo(OnceLock<String>);

impl ModelDigestMemo {
    pub(crate) fn digest(&self, model: &impl Serialize) -> Result<String, serde_json::Error> {
        if let Some(digest) = self.0.get() {
            return Ok(digest.clone());
        }
        let mut writer = BufWriter::with_capacity(64 * 1024, DigestWriter(Sha256::new()));
        serde_json::to_writer_pretty(&mut writer, model)?;
        writer.write_all(b"\n").map_err(serde_json::Error::io)?;
        writer.flush().map_err(serde_json::Error::io)?;
        let digest = format!("sha256:{:x}", writer.get_ref().0.clone().finalize());
        // Simultaneous first readers may compute identical digests; set never
        // replaces an established result. Readers never share mutable model data.
        let _ = self.0.set(digest.clone());
        Ok(digest)
    }
}

impl Debug for ModelDigestMemo {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelDigestMemo")
            .finish_non_exhaustive()
    }
}

impl PartialEq for ModelDigestMemo {
    fn eq(&self, _other: &Self) -> bool {
        // Equality of every semantic field remains derived by the owning model.
        // Operational memo population must not change that equality.
        true
    }
}

impl Eq for ModelDigestMemo {}

struct DigestWriter(Sha256);

impl Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
