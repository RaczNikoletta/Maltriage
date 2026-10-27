//! Static feature extraction from executable binaries (currently PE; ELF planned).
//!
//! This crate is the single source of truth for features: the same code feeds
//! model training (via `bin-cli`) and inference, which avoids train/serve skew.
//! Input is treated as hostile: no panicking indexing, bounded work.

pub mod entropy;
pub mod imports;
pub mod strings;

use goblin::pe::PE;
use serde::Serialize;

pub use imports::{ImportStats, HASH_BUCKETS};
pub use strings::StringStats;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
/// Data directory indexes.
const DIR_CERTIFICATE: usize = 4;
const DIR_TLS: usize = 9;

const STANDARD_SECTIONS: &[&str] = &[
    ".text", ".data", ".rdata", ".idata", ".edata", ".pdata", ".rsrc", ".reloc", ".bss", ".tls",
    ".crt", ".didat", ".gfids", ".xdata", ".cormeta",
];

#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("not a valid PE file: {0}")]
    Parse(#[from] goblin::error::Error),
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct HeaderFeatures {
    pub machine: u16,
    pub timestamp: u32,
    pub characteristics: u16,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub size_of_code: u32,
    pub entry_point: u32,
    pub is_64: bool,
    pub is_dll: bool,
    pub has_signature: bool,
    pub has_tls: bool,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct SectionFeatures {
    pub count: u32,
    pub mean_entropy: f64,
    pub max_entropy: f64,
    pub writable_executable: u32,
    pub nonstandard_names: u32,
    pub zero_raw_size: u32,
    pub max_vsize_ratio: f64,
    pub overlay_size: u64,
    pub overlay_ratio: f64,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct PeFeatures {
    pub file_size: u64,
    pub byte_entropy: f64,
    pub header: HeaderFeatures,
    pub sections: SectionFeatures,
    pub imports: ImportStats,
    pub strings: StringStats,
    /// Normalized byte histogram, length 256.
    pub byte_hist: Vec<f32>,
}

/// Parse `bytes` as a PE file and compute all features.
pub fn extract(bytes: &[u8]) -> Result<PeFeatures, ExtractError> {
    let pe = PE::parse(bytes)?;

    let header = header_features(&pe);
    let sections = section_features(&pe, bytes, header.size_of_headers);
    let imports = imports::import_stats(pe.imports.iter().map(|i| (&*i.dll, &*i.name)));

    Ok(PeFeatures {
        file_size: bytes.len() as u64,
        byte_entropy: entropy::shannon(bytes),
        header,
        sections,
        imports,
        strings: strings::string_stats(bytes),
        byte_hist: entropy::byte_histogram(bytes),
    })
}

fn header_features(pe: &PE) -> HeaderFeatures {
    let coff = &pe.header.coff_header;
    let mut h = HeaderFeatures {
        machine: coff.machine,
        timestamp: coff.time_date_stamp,
        characteristics: coff.characteristics,
        is_64: pe.is_64,
        is_dll: pe.is_lib,
        ..Default::default()
    };
    if let Some(opt) = &pe.header.optional_header {
        h.subsystem = opt.windows_fields.subsystem as u16;
        h.dll_characteristics = opt.windows_fields.dll_characteristics as u16;
        h.size_of_image = opt.windows_fields.size_of_image as u32;
        h.size_of_headers = opt.windows_fields.size_of_headers as u32;
        h.size_of_code = opt.standard_fields.size_of_code as u32;
        h.entry_point = opt.standard_fields.address_of_entry_point as u32;
        let dirs = &opt.data_directories.data_directories;
        h.has_signature = dirs.get(DIR_CERTIFICATE).is_some_and(|d| d.is_some());
        h.has_tls = dirs.get(DIR_TLS).is_some_and(|d| d.is_some());
    }
    h
}

fn section_features(pe: &PE, bytes: &[u8], size_of_headers: u32) -> SectionFeatures {
    let mut f = SectionFeatures {
        count: pe.sections.len() as u32,
        ..Default::default()
    };
    let file_len = bytes.len();
    let mut last_end = (size_of_headers as usize).min(file_len);
    let mut entropy_sum = 0.0;

    for s in &pe.sections {
        let start = s.pointer_to_raw_data as usize;
        let end = start.saturating_add(s.size_of_raw_data as usize);
        // Hostile input: the declared range may lie outside the file.
        let data = bytes.get(start..end).unwrap_or(&[]);
        if !data.is_empty() {
            last_end = last_end.max(end.min(file_len));
        }

        let e = entropy::shannon(data);
        entropy_sum += e;
        f.max_entropy = f.max_entropy.max(e);

        let ch = s.characteristics;
        if ch & IMAGE_SCN_MEM_EXECUTE != 0 && ch & IMAGE_SCN_MEM_WRITE != 0 {
            f.writable_executable += 1;
        }
        let name = s.name().unwrap_or("").to_ascii_lowercase();
        if !STANDARD_SECTIONS.contains(&name.as_str()) {
            f.nonstandard_names += 1;
        }
        if s.size_of_raw_data == 0 {
            f.zero_raw_size += 1;
        }
        let ratio = s.virtual_size as f64 / s.size_of_raw_data.max(1) as f64;
        f.max_vsize_ratio = f.max_vsize_ratio.max(ratio);
    }

    f.mean_entropy = entropy_sum / f.count.max(1) as f64;
    f.overlay_size = (file_len - last_end) as u64;
    f.overlay_ratio = f.overlay_size as f64 / file_len.max(1) as f64;
    f
}

impl PeFeatures {
    /// Ordered `(name, value)` pairs: the model's input vector.
    /// Order and names are part of the contract with the training pipeline.
    pub fn flatten(&self) -> Vec<(String, f32)> {
        let mut v: Vec<(String, f32)> = Vec::with_capacity(600);
        let mut push = |name: &str, value: f64| v.push((name.to_string(), value as f32));

        push("file_size", self.file_size as f64);
        push("byte_entropy", self.byte_entropy);

        let h = &self.header;
        push("hdr_machine", h.machine.into());
        push("hdr_timestamp", h.timestamp.into());
        push("hdr_characteristics", h.characteristics.into());
        push("hdr_subsystem", h.subsystem.into());
        push("hdr_dll_characteristics", h.dll_characteristics.into());
        push("hdr_size_of_image", h.size_of_image.into());
        push("hdr_size_of_headers", h.size_of_headers.into());
        push("hdr_size_of_code", h.size_of_code.into());
        push("hdr_entry_point", h.entry_point.into());
        push("hdr_is_64", h.is_64 as u8 as f64);
        push("hdr_is_dll", h.is_dll as u8 as f64);
        push("hdr_has_signature", h.has_signature as u8 as f64);
        push("hdr_has_tls", h.has_tls as u8 as f64);

        let s = &self.sections;
        push("sec_count", s.count.into());
        push("sec_mean_entropy", s.mean_entropy);
        push("sec_max_entropy", s.max_entropy);
        push("sec_writable_executable", s.writable_executable.into());
        push("sec_nonstandard_names", s.nonstandard_names.into());
        push("sec_zero_raw_size", s.zero_raw_size.into());
        push("sec_max_vsize_ratio", s.max_vsize_ratio);
        push("sec_overlay_size", s.overlay_size as f64);
        push("sec_overlay_ratio", s.overlay_ratio);

        let i = &self.imports;
        push("imp_count", i.count.into());
        push("imp_dll_count", i.dll_count.into());
        push("imp_suspicious", i.suspicious.into());

        let t = &self.strings;
        push("str_count", t.count.into());
        push("str_avg_len", t.avg_len.into());
        push("str_max_len", t.max_len.into());
        push("str_urls", t.urls.into());
        push("str_ips", t.ips.into());
        push("str_registry", t.registry.into());
        push("str_paths", t.paths.into());

        // Fixed-width blocks: always emit the full width so default/empty values
        // produce the same column layout as real ones.
        for n in 0..HASH_BUCKETS {
            push(&format!("imp_hash_{n:03}"), *i.hashed.get(n).unwrap_or(&0.0) as f64);
        }
        for n in 0..256 {
            push(&format!("hist_{n:03}"), *self.byte_hist.get(n).unwrap_or(&0.0) as f64);
        }
        v
    }

    /// Column names, in the same order as `flatten()`.
    pub fn feature_names() -> Vec<String> {
        Self::default().flatten().into_iter().map(|(n, _)| n).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_is_rejected() {
        assert!(extract(b"definitely not a PE file").is_err());
        assert!(extract(&[]).is_err());
        assert!(extract(b"MZ").is_err());
    }

    #[test]
    fn feature_layout_is_stable() {
        let names = PeFeatures::feature_names();
        assert_eq!(names.len(), PeFeatures::default().flatten().len());
        assert_eq!(names[0], "file_size");
        assert!(names.contains(&"hist_255".to_string()));
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "feature names must be unique");
    }
}
