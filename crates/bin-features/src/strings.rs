use regex::RegexSet;
use serde::Serialize;
use std::sync::OnceLock;

const MIN_LEN: usize = 5;
/// Hard caps: the input is untrusted, bound the work done per file.
const MAX_STRINGS: u32 = 200_000;
const MAX_MATCH_LEN: usize = 2048;

#[derive(Debug, Default, Clone, Serialize)]
pub struct StringStats {
    pub count: u32,
    pub avg_len: f32,
    pub max_len: u32,
    pub urls: u32,
    pub ips: u32,
    pub registry: u32,
    pub paths: u32,
}

fn patterns() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| {
        RegexSet::new([
            r"(?i)https?://",
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            r"(?i)HKEY_|\\CurrentVersion\\",
            r"(?i)\b[a-z]:\\",
        ])
        .expect("static patterns are valid")
    })
}

/// Statistics over printable ASCII runs (like `strings`) found anywhere in the file.
pub fn string_stats(data: &[u8]) -> StringStats {
    let set = patterns();
    let mut stats = StringStats::default();
    let mut total_len: u64 = 0;

    for run in data.split(|b| !(0x20..=0x7e).contains(b)) {
        if run.len() < MIN_LEN {
            continue;
        }
        if stats.count >= MAX_STRINGS {
            break;
        }
        stats.count += 1;
        total_len += run.len() as u64;
        stats.max_len = stats.max_len.max(run.len() as u32);

        if run.len() <= MAX_MATCH_LEN {
            if let Ok(text) = std::str::from_utf8(run) {
                let m = set.matches(text);
                stats.urls += m.matched(0) as u32;
                stats.ips += m.matched(1) as u32;
                stats.registry += m.matched(2) as u32;
                stats.paths += m.matched(3) as u32;
            }
        }
    }
    stats.avg_len = total_len as f32 / stats.count.max(1) as f32;
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_and_classifies_strings() {
        let data = b"\x00\x01http://evil.example/a\x00ab\x00C:\\Windows\\x.exe\x00 10.0.0.5 \x00HKEY_LOCAL_MACHINE\x00";
        let s = string_stats(data);
        assert_eq!(s.count, 4);
        assert_eq!(s.urls, 1);
        assert_eq!(s.ips, 1);
        assert_eq!(s.registry, 1);
        assert_eq!(s.paths, 1);
    }

    #[test]
    fn short_runs_are_ignored() {
        assert_eq!(string_stats(b"ab\x00cd\x00").count, 0);
    }
}
