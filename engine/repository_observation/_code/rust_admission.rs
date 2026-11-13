//! Resource admission before existing Rust frontends; no symbol or intent model.

/// Admits bounded Rust source before recursive parser and visitor allocation.
///
/// Strings, raw strings, character literals and nested comments are skipped only
/// to measure delimiter nesting. The existing Rust frontend remains the sole
/// syntax authority. Long expression/operator runs are conservatively rejected.
///
/// # Errors
/// Returns `RESOURCE_LIMIT` without a partial semantic result on exhaustion.
pub fn admit_rust(source: &str) -> Result<(), &'static str> {
    const LIMIT: &str = "RESOURCE_LIMIT: Rust source admission exhausted";
    let bytes = source.as_bytes();
    if bytes.len() > super::MAX_SOURCE_UNIT_BYTES {
        return Err("RESOURCE_LIMIT: Rust source bytes exceed 4 MiB");
    }
    let (mut i, mut depth, mut operators) = (0, 0_usize, 0_usize);
    let (mut angles, mut angle_depth) = (0_usize, 0_usize);
    while i < bytes.len() {
        if bytes[i..].starts_with(b"//") {
            i += bytes[i..]
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(bytes.len() - i);
        } else if bytes[i..].starts_with(b"/*") {
            let mut comments = 1_usize;
            i += 2;
            while i < bytes.len() && comments != 0 {
                if bytes[i..].starts_with(b"/*") {
                    comments += 1;
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    comments -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
                if comments > 128 {
                    return Err(LIMIT);
                }
            }
        } else if matches!(bytes[i], b'b' | b'c')
            && bytes.get(i + 1) == Some(&b'r')
            && raw_string_end(bytes, i + 1).is_some()
        {
            i = raw_string_end(bytes, i + 1).unwrap_or(bytes.len());
        } else if bytes[i] == b'r' && raw_string_end(bytes, i).is_some() {
            i = raw_string_end(bytes, i).unwrap_or(bytes.len());
        } else if bytes[i] == b'"' {
            i = quoted_end(bytes, i);
        } else if bytes[i] == b'\'' && character_end(source, i).is_some() {
            i = character_end(source, i).unwrap_or(bytes.len());
        } else if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            if matches!(
                &source[start..i],
                "return" | "break" | "yield" | "box" | "move" | "async"
            ) {
                operators += 1;
                if operators > 256 {
                    return Err(
                        "RESOURCE_LIMIT: Rust operator or recursive-keyword run exceeds 256",
                    );
                }
            }
        } else {
            if bytes[i] == b'<' {
                angles += 1;
                angle_depth += 1;
                if angles > 512 || angle_depth > 128 {
                    return Err(
                        "RESOURCE_LIMIT: Rust angle admission exceeds 512 total or 128 nested",
                    );
                }
            } else if bytes[i] == b'>' {
                angle_depth = angle_depth.saturating_sub(1);
            }
            match bytes[i] {
                b'(' | b'[' | b'{' => {
                    depth += 1;
                    if depth > 128 {
                        return Err(LIMIT);
                    }
                }
                b')' | b']' | b'}' => {
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
            if matches!(bytes[i], b';' | b'{' | b'}') {
                operators = 0;
            } else if b"+-*/&|^=!?~.<>".contains(&bytes[i]) {
                operators += 1;
                if operators > 256 {
                    return Err(
                        "RESOURCE_LIMIT: Rust operator or recursive-keyword run exceeds 256",
                    );
                }
            }
            i += 1;
        }
    }
    Ok(())
}

fn quoted_end(bytes: &[u8], mut i: usize) -> usize {
    i += 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i = (i + 2).min(bytes.len());
        } else if bytes[i] == b'"' {
            return i + 1;
        } else {
            i += 1;
        }
    }
    i
}

fn raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while bytes.get(i) == Some(&b'#') {
        i += 1;
    }
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    let hashes = i - start - 1;
    i += 1;
    while i < bytes.len() {
        if bytes[i] == b'"'
            && bytes
                .get(i + 1..i + 1 + hashes)
                .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
        {
            return Some(i + 1 + hashes);
        }
        i += 1;
    }
    Some(i)
}

fn character_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut i = start + 1;
    if bytes.get(i) == Some(&b'\\') {
        i += 1;
        match *bytes.get(i)? {
            b'u' => {
                i += 1;
                if bytes.get(i) != Some(&b'{') {
                    return None;
                }
                i += 1;
                while bytes
                    .get(i)
                    .is_some_and(|byte| byte.is_ascii_hexdigit() || *byte == b'_')
                {
                    i += 1;
                }
                if bytes.get(i) != Some(&b'}') {
                    return None;
                }
                i += 1;
            }
            b'x' => {
                i += 3;
            }
            _ => {
                i += 1;
            }
        }
    } else {
        i += source.get(i..)?.chars().next()?.len_utf8();
    }
    (bytes.get(i) == Some(&b'\'')).then_some(i + 1)
}
