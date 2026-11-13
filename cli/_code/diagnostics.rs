//! Streaming terminal-safe diagnostics; machine output is never transformed.
use std::io::{self, Write};

pub(super) struct DiagnosticWriter<'a, W: Write> {
    inner: &'a mut W,
    pending: [u8; 4],
    used: usize,
}

impl<'a, W: Write> DiagnosticWriter<'a, W> {
    pub(super) const fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            pending: [0; 4],
            used: 0,
        }
    }

    fn escape_pending(&mut self) -> io::Result<()> {
        let used = std::mem::replace(&mut self.used, 0);
        for byte in &self.pending[..used] {
            write!(self.inner, "\\x{byte:02x}")?;
        }
        Ok(())
    }
}

impl<W: Write> Write for DiagnosticWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for byte in bytes {
            self.pending[self.used] = *byte;
            self.used += 1;
            match std::str::from_utf8(&self.pending[..self.used]) {
                Ok(value) => {
                    self.used = 0;
                    for character in value.chars() {
                        if (character.is_control() && !matches!(character, '\n' | '\t'))
                            || matches!(character, '\u{61c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
                        {
                            write!(self.inner, "{}", character.escape_default())?;
                        } else {
                            let mut encoded = [0_u8; 4];
                            self.inner
                                .write_all(character.encode_utf8(&mut encoded).as_bytes())?;
                        }
                    }
                }
                Err(error) if error.error_len().is_some() || self.used == 4 => {
                    self.escape_pending()?;
                }
                Err(_) => {}
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.escape_pending()?;
        self.inner.flush()
    }
}
