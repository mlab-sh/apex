//! Shared helpers: filesystem walking, lossy text reads, regex compilation,
//! Shannon entropy, and line-number computation.

use fancy_regex::Regex;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Read a file as UTF-8, replacing invalid sequences (like Python errors="replace").
pub fn read_text(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// All files under `root` (recursively).
pub fn walk_all_files(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect()
}

/// Files whose extension (lowercased, without dot) is one of `exts`, grouped by
/// extension order then sorted within each group for deterministic output.
pub fn find_files_by_ext(root: &Path, exts: &[&str]) -> Vec<PathBuf> {
    let all = walk_all_files(root);
    let mut out = Vec::new();
    for ext in exts {
        let mut group: Vec<PathBuf> = all
            .iter()
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case(ext))
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        group.sort();
        out.extend(group);
    }
    out
}

/// Relative path from `root`, using forward slashes.
pub fn rel(path: &Path, root: &Path) -> String {
    let r = path.strip_prefix(root).unwrap_or(path);
    r.to_string_lossy().replace('\\', "/")
}

/// 1-indexed line number of a byte offset within `content`.
pub fn line_of(content: &str, byte_offset: usize) -> u64 {
    let end = byte_offset.min(content.len());
    content[..end].bytes().filter(|&b| b == b'\n').count() as u64 + 1
}

/// Compile a regex with optional Python-style flags (i=IGNORECASE, s=DOTALL, m=MULTILINE).
pub fn rx_flags(pattern: &str, i: bool, s: bool, m: bool) -> Regex {
    let mut fl = String::new();
    if i {
        fl.push('i');
    }
    if s {
        fl.push('s');
    }
    if m {
        fl.push('m');
    }
    let full = if fl.is_empty() {
        pattern.to_string()
    } else {
        format!("(?{fl}:{pattern})")
    };
    Regex::new(&full).unwrap_or_else(|e| panic!("bad regex {pattern:?}: {e}"))
}

pub fn rx(pattern: &str) -> Regex {
    rx_flags(pattern, false, false, false)
}

/// Mimic Python's `str.splitlines()`: split on the same line boundaries and
/// drop a trailing empty line when the string ends on a boundary.
pub fn py_splitlines(s: &str) -> Vec<&str> {
    let is_boundary = |c: char| {
        matches!(
            c,
            '\n' | '\r'
                | '\u{0b}'
                | '\u{0c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        )
    };
    let mut lines = Vec::new();
    let bytes = s.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    let mut idx = 0usize;
    while idx < chars.len() {
        let (bi, c) = chars[idx];
        if is_boundary(c) {
            lines.push(&s[start..bi]);
            // Handle \r\n as a single boundary.
            let mut next = bi + c.len_utf8();
            if c == '\r' && next < bytes.len() && bytes[next] == b'\n' {
                next += 1;
                idx += 1;
            }
            start = next;
            i = next;
        }
        idx += 1;
        let _ = i;
    }
    if start < s.len() {
        lines.push(&s[start..]);
    }
    lines
}

/// Shannon entropy of a string (over its characters).
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    let mut len = 0usize;
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
        len += 1;
    }
    let len = len as f64;
    -freq
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Number of distinct characters.
pub fn distinct_chars(s: &str) -> usize {
    s.chars().collect::<std::collections::HashSet<_>>().len()
}
