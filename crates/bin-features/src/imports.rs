use serde::Serialize;
use std::collections::HashSet;

/// Number of feature-hashing buckets for `dll!function` import names.
pub const HASH_BUCKETS: usize = 256;
const MAX_IMPORTS: usize = 100_000;

/// APIs commonly abused for injection, persistence, download/exec and anti-analysis.
const SUSPICIOUS: &[&str] = &[
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "GetAsyncKeyState",
    "OpenProcess",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "RegSetValueExA",
    "RegSetValueExW",
    "CryptEncrypt",
    "InternetOpenA",
    "InternetOpenW",
];

#[derive(Debug, Clone, Serialize)]
pub struct ImportStats {
    pub count: u32,
    pub dll_count: u32,
    pub suspicious: u32,
    /// Feature-hashed counts, length == `HASH_BUCKETS`.
    pub hashed: Vec<f32>,
}

impl Default for ImportStats {
    fn default() -> Self {
        Self {
            count: 0,
            dll_count: 0,
            suspicious: 0,
            hashed: vec![0.0; HASH_BUCKETS],
        }
    }
}

/// FNV-1a: tiny, stable across platforms/versions (unlike `DefaultHasher`).
pub fn fnv1a(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in bytes {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// `imports` yields `(dll, function)` pairs.
pub fn import_stats<'a>(imports: impl Iterator<Item = (&'a str, &'a str)>) -> ImportStats {
    let mut stats = ImportStats::default();
    let mut dlls: HashSet<String> = HashSet::new();

    for (dll, func) in imports.take(MAX_IMPORTS) {
        let dll = dll.to_ascii_lowercase();
        let key = format!("{}!{}", dll, func.to_ascii_lowercase());
        stats.hashed[fnv1a(key.as_bytes()) as usize % HASH_BUCKETS] += 1.0;
        stats.count += 1;
        if SUSPICIOUS.iter().any(|s| s.eq_ignore_ascii_case(func)) {
            stats.suspicious += 1;
        }
        dlls.insert(dll);
    }
    stats.dll_count = dlls.len() as u32;
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_known_vectors() {
        assert_eq!(fnv1a(b""), 0x811c_9dc5);
        assert_eq!(fnv1a(b"a"), 0xe40c_292c);
    }

    #[test]
    fn counts_dlls_and_suspicious_apis() {
        let imports = [
            ("KERNEL32.dll", "VirtualAlloc"),
            ("kernel32.dll", "CreateFileW"),
            ("USER32.dll", "MessageBoxA"),
        ];
        let s = import_stats(imports.iter().copied());
        assert_eq!(s.count, 3);
        assert_eq!(s.dll_count, 2);
        assert_eq!(s.suspicious, 1);
        assert_eq!(s.hashed.iter().sum::<f32>(), 3.0);
    }
}
