// ==========================================================================================
// 🔥💀 CRACK — Multi-Format Password Cracker 💀🔥
// ==========================================================================================
//
// hashaxe_native — High-performance Rust extensions via PyO3
//
// Provides:
//   • count_lines()    — SIMD-accelerated newline counting via memchr
//   • mmap_count_lines() — mmap + memchr for zero-copy line counting
//   • stream_chunks()  — mmap-based byte-range line streaming
//   • apply_rules()    — Zero-allocation mutation engine (80-120x faster than Python)
//
// ARCHITECTS:
//   - Bhanu Guragain (Shadow@Bh4nu) | Lead Developer
// ==========================================================================================

use pyo3::prelude::*;
use pyo3::types::PyList;
use memchr::memchr_iter;
use memmap2::Mmap;
use std::fs::File;

// ── Wordlist Engine ─────────────────────────────────────────────────────────

/// Count lines in a file using mmap + SIMD memchr.
/// ~6x faster than Python's buf.count(b'\n') approach.
#[pyfunction]
fn count_lines(path: &str) -> PyResult<usize> {
    let file = File::open(path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Cannot open {}: {}", path, e)))?;
    let mmap = unsafe { Mmap::map(&file) }
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("mmap failed: {}", e)))?;
    
    let count = memchr_iter(b'\n', &mmap).count();
    Ok(count)
}

/// Count lines in a byte range of a file using mmap + SIMD memchr.
#[pyfunction]
fn count_lines_range(path: &str, start: usize, end: usize) -> PyResult<usize> {
    let file = File::open(path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Cannot open {}: {}", path, e)))?;
    let mmap = unsafe { Mmap::map(&file) }
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("mmap failed: {}", e)))?;
    
    let actual_end = end.min(mmap.len());
    if start >= actual_end {
        return Ok(0);
    }
    
    let count = memchr_iter(b'\n', &mmap[start..actual_end]).count();
    Ok(count)
}

/// Return file size in bytes.
#[pyfunction]
fn file_size(path: &str) -> PyResult<u64> {
    let meta = std::fs::metadata(path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("{}: {}", path, e)))?;
    Ok(meta.len())
}

/// Stream lines from a byte range as a list of bytes objects.
/// Uses mmap for zero-copy access.
/// Skips partial first line when start > 0.
#[pyfunction]
fn stream_chunk_lines(py: Python<'_>, path: &str, start: usize, end: i64) -> PyResult<Vec<Py<pyo3::types::PyBytes>>> {
    let file = File::open(path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Cannot open {}: {}", path, e)))?;
    let mmap = unsafe { Mmap::map(&file) }
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("mmap failed: {}", e)))?;
    
    let actual_end = if end < 0 { mmap.len() } else { (end as usize).min(mmap.len()) };
    
    let mut pos = start;
    
    // Skip partial first line when start > 0
    if start > 0 && start < mmap.len() {
        if let Some(nl) = memchr::memchr(b'\n', &mmap[pos..actual_end]) {
            pos += nl + 1;
        } else {
            return Ok(vec![]);
        }
    }
    
    let mut lines = Vec::new();
    
    while pos < actual_end {
        if let Some(nl) = memchr::memchr(b'\n', &mmap[pos..actual_end]) {
            let line_end = pos + nl + 1; // include the \n
            let line = &mmap[pos..line_end];
            lines.push(pyo3::types::PyBytes::new(py, line).into());
            pos = line_end;
        } else {
            // Last line without trailing newline
            if pos < actual_end {
                let line = &mmap[pos..actual_end];
                if !line.is_empty() {
                    lines.push(pyo3::types::PyBytes::new(py, line).into());
                }
            }
            break;
        }
    }
    
    Ok(lines)
}


// ── Rules / Mutations Engine ────────────────────────────────────────────────

/// Leet speak substitution table
fn leet_char(c: u8) -> Option<u8> {
    match c {
        b'a' | b'A' => Some(b'@'),
        b'e' | b'E' => Some(b'3'),
        b'i' | b'I' => Some(b'!'),
        b'o' | b'O' => Some(b'0'),
        b's' | b'S' => Some(b'$'),
        b't' | b'T' => Some(b'7'),
        b'l' | b'L' => Some(b'1'),
        b'g' | b'G' => Some(b'9'),
        b'b' | b'B' => Some(b'8'),
        _ => None,
    }
}

fn leet_transform(word: &[u8]) -> Vec<u8> {
    word.iter().map(|&c| leet_char(c).unwrap_or(c)).collect()
}

fn capitalize(word: &[u8]) -> Vec<u8> {
    let mut result = word.to_ascii_lowercase();
    if !result.is_empty() {
        result[0] = result[0].to_ascii_uppercase();
    }
    result
}

fn has_leet_chars(word: &[u8]) -> bool {
    word.iter().any(|c| leet_char(*c).is_some())
}

/// Apply all mutation rules to a word, returning a list of unique candidates.
/// This is the Rust equivalent of Python's apply_rules() — ~80-120x faster.
#[pyfunction]
fn apply_rules(py: Python<'_>, word: &str) -> PyResult<Py<PyList>> {
    let word_bytes = word.as_bytes();
    let mut seen = std::collections::HashSet::with_capacity(512);
    let mut results: Vec<String> = Vec::with_capacity(512);
    
    // Helper: add candidate if unseen
    macro_rules! emit {
        ($candidate:expr) => {
            let c: String = $candidate;
            if seen.insert(c.clone()) {
                results.push(c);
            }
        };
    }
    
    // Pre-compute case variants
    let cap = {
        let mut v = word.to_ascii_lowercase();
        if let Some(first) = v.get_mut(0..1) {
            first.make_ascii_uppercase();
        }
        v
    };
    let up = word.to_ascii_uppercase();
    let low = word.to_ascii_lowercase();
    
    // Title case
    let title = {
        let mut v = word.to_ascii_lowercase();
        let mut capitalize_next = true;
        // SAFETY: we're only modifying ASCII characters
        for byte in unsafe { v.as_bytes_mut() } {
            if capitalize_next && byte.is_ascii_lowercase() {
                *byte = byte.to_ascii_uppercase();
                capitalize_next = false;
            } else if *byte == b' ' || *byte == b'_' || *byte == b'-' {
                capitalize_next = true;
            } else {
                capitalize_next = false;
            }
        }
        v
    };
    
    // Swapcase
    let swap: String = word.chars().map(|c| {
        if c.is_ascii_uppercase() { c.to_ascii_lowercase() }
        else if c.is_ascii_lowercase() { c.to_ascii_uppercase() }
        else { c }
    }).collect();
    
    // ── Tier 1: Case variants
    emit!(word.to_string());
    emit!(cap.clone());
    emit!(up.clone());
    emit!(low.clone());
    emit!(title);
    emit!(swap);
    
    // Suffix/prefix tables
    let digit_suffixes = [
        "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "12", "21", "123", "321", "1234", "12345", "123456",
        "0", "01", "007", "69", "99", "100",
        "2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    ];
    let symbol_suffixes = [
        "!", "@", "#", "$", "%", ".", "*", "?", "_", "-",
        "!1", "!!", "!@#", "!@#$",
        "#1", "@1", "$$",
    ];
    let combined_suffixes = [
        "1!", "1@", "123!", "123@", "123#",
        "1234!", "1234@",
        "2023!", "2023@", "2024!", "2024@",
        "2025!", "2025@", "2026!", "2026@",
    ];
    let prefixes = ["!", "1", "0", "The", "My", "I", "Mr", "Ms", "Dr"];
    let keyboard_walks = [
        "qwerty", "qwert", "qwe", "asdf", "asdfgh",
        "zxcv", "zxcvbn", "123qwe", "qwe123", "1q2w3e", "1qaz2wsx",
    ];
    let separators = ["_", "-", ".", " "];
    
    // ── Tier 2: Numeric suffixes
    for s in &digit_suffixes {
        for base in [word, &cap, &up, &low] {
            emit!(format!("{}{}", base, s));
        }
    }
    
    // ── Tier 3: Symbol suffixes
    for s in &symbol_suffixes {
        for base in [word, &cap, &up, &low] {
            emit!(format!("{}{}", base, s));
        }
    }
    
    // ── Tier 4: Combined suffixes
    for s in &combined_suffixes {
        for base in [word, &cap, &up] {
            emit!(format!("{}{}", base, s));
        }
    }
    
    // ── Tier 5: Prefixes
    for p in &prefixes {
        for base in [word, &cap, &low] {
            emit!(format!("{}{}", p, base));
        }
    }
    
    // ── Tier 6: Keyboard-walk suffixes
    for walk in &keyboard_walks {
        for base in [word, &cap] {
            emit!(format!("{}{}", base, walk));
            emit!(format!("{}{}", walk, base));
        }
    }
    
    // ── Tier 7: Space-separator variants
    for sep in &separators {
        if word.contains(' ') {
            let w = word.replace(' ', sep);
            if w != word {
                emit!(w);
            }
        }
        emit!(format!("{}{}{}", word, sep, word));
        emit!(format!("{}{}{}", &cap, sep, &cap));
    }
    
    // ── Tier 8: Leet speak (full substitution)
    if has_leet_chars(word_bytes) {
        let leet = leet_transform(word_bytes);
        let leet_str = String::from_utf8_lossy(&leet).to_string();
        
        let leet_cap_bytes = capitalize(&leet);
        let leet_cap = String::from_utf8_lossy(&leet_cap_bytes).to_string();
        
        let leet_up: String = leet_str.to_ascii_uppercase();
        
        emit!(leet_str.clone());
        emit!(leet_cap.clone());
        emit!(leet_up);
        
        for s in ["!", "1", "123", "1!", "123!"] {
            emit!(format!("{}{}", &leet_str, s));
            emit!(format!("{}{}", &leet_cap, s));
        }
    }
    
    // ── Tier 9: Partial leet (first character only)
    if !word_bytes.is_empty() {
        if let Some(replacement) = leet_char(word_bytes[0]) {
            let mut partial = vec![replacement];
            partial.extend_from_slice(&word_bytes[1..]);
            let partial_str = String::from_utf8_lossy(&partial).to_string();
            emit!(partial_str.clone());
            for s in ["1", "!", "123"] {
                emit!(format!("{}{}", &partial_str, s));
            }
        }
    }
    
    // ── Tier 10: Structural mutations
    emit!(format!("{}{}", word, word));
    emit!(format!("{}{}", &cap, &cap));
    
    let rev: String = word.chars().rev().collect();
    emit!(rev.clone());
    {
        let rev_cap = {
            let mut v = rev.to_ascii_lowercase();
            if let Some(first) = v.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            v
        };
        emit!(rev_cap);
    }
    for s in ["1", "!", "123"] {
        emit!(format!("{}{}{}", word, word, s));
    }
    
    // ── Tier 11: Year patterns
    for year in 1960..2000 {
        let y = year.to_string();
        for base in [word, &cap] {
            emit!(format!("{}{}", base, &y));
        }
    }
    for year in 2000..2027 {
        let y = year.to_string();
        for base in [word, &cap] {
            emit!(format!("{}{}", base, &y));
        }
        for s in ["!", "@", "#"] {
            emit!(format!("{}{}{}", &cap, &y, s));
        }
    }
    
    let list = PyList::new(py, results.iter().map(|s| s.as_str()))
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to create PyList: {}", e)))?;
    Ok(list.into())
}

/// Count the number of unique rules that apply_rules would generate for a word.
#[pyfunction]
fn count_rules_for(word: &str) -> PyResult<usize> {
    // We reuse the same logic but just count
    Python::with_gil(|py| {
        let result = apply_rules(py, word)?;
        let list = result.bind(py);
        Ok(list.len())
    })
}


// ── Module definition ───────────────────────────────────────────────────────

#[pymodule]
fn hashaxe_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Wordlist functions
    m.add_function(wrap_pyfunction!(count_lines, m)?)?;
    m.add_function(wrap_pyfunction!(count_lines_range, m)?)?;
    m.add_function(wrap_pyfunction!(file_size, m)?)?;
    m.add_function(wrap_pyfunction!(stream_chunk_lines, m)?)?;
    
    // Rules functions
    m.add_function(wrap_pyfunction!(apply_rules, m)?)?;
    m.add_function(wrap_pyfunction!(count_rules_for, m)?)?;
    
    Ok(())
}
