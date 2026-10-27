use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use bin_features::PeFeatures;
use rayon::prelude::*;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

const PE_EXTENSIONS: &[&str] = &["exe", "dll", "sys", "scr", "ocx", "cpl", "drv", "efi"];

#[derive(Parser)]
#[command(name = "maltriage", version, about = "Static malware triage: feature extraction")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Extract features from files/directories, one JSON object per line.
    Extract(ExtractArgs),
    /// Print the model input column names, one per line.
    Names,
}

#[derive(Args)]
struct ExtractArgs {
    /// Files or directories (directories are walked recursively).
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    /// Write JSONL here instead of stdout.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Attach a label (e.g. "malicious" / "benign") to every record.
    #[arg(long)]
    label: Option<String>,
    /// Skip files larger than this many MiB.
    #[arg(long, default_value_t = 64)]
    max_size_mb: u64,
    /// In directories, process every file, not only PE-like extensions
    /// (needed for sample sets named by hash).
    #[arg(long)]
    all_files: bool,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Names => {
            for name in PeFeatures::feature_names() {
                println!("{name}");
            }
            Ok(())
        }
        Command::Extract(args) => extract(args),
    }
}

fn extract(args: ExtractArgs) -> Result<()> {
    let files = collect_files(&args.paths, args.all_files);
    let max_bytes = args.max_size_mb.saturating_mul(1024 * 1024);

    let records: Vec<Value> = files
        .par_iter()
        .map(|p| process(p, max_bytes, args.label.as_deref()))
        .collect();

    let mut out: Box<dyn Write> = match &args.out {
        Some(path) => Box::new(BufWriter::new(
            fs::File::create(path).with_context(|| format!("creating {}", path.display()))?,
        )),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };
    for record in &records {
        serde_json::to_writer(&mut out, record)?;
        out.write_all(b"\n")?;
    }
    out.flush()?;

    let failed = records.iter().filter(|r| r.get("error").is_some()).count();
    eprintln!("processed {} files, {} failed", records.len(), failed);
    Ok(())
}

fn collect_files(paths: &[PathBuf], all_files: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_dir() {
            // Do not follow symlinks: samples may be hostile.
            for entry in WalkDir::new(path).follow_links(false).into_iter().flatten() {
                if entry.file_type().is_file() && (all_files || has_pe_extension(entry.path())) {
                    files.push(entry.into_path());
                }
            }
        } else {
            files.push(path.clone());
        }
    }
    files
}

fn has_pe_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| PE_EXTENSIONS.iter().any(|p| p.eq_ignore_ascii_case(e)))
}

fn process(path: &Path, max_bytes: u64, label: Option<&str>) -> Value {
    let display = path.display().to_string();
    match try_process(path, max_bytes, label) {
        Ok(v) => v,
        Err(e) => json!({ "path": display, "error": format!("{e:#}") }),
    }
}

fn try_process(path: &Path, max_bytes: u64, label: Option<&str>) -> Result<Value> {
    let size = fs::metadata(path)?.len();
    anyhow::ensure!(size <= max_bytes, "file too large ({size} bytes)");

    let bytes = fs::read(path)?;
    let features = bin_features::extract(&bytes)?;

    let mut feature_map = Map::new();
    for (name, value) in features.flatten() {
        feature_map.insert(name, json!(value));
    }

    let mut record = Map::new();
    record.insert("path".into(), json!(path.display().to_string()));
    record.insert("sha256".into(), json!(format!("{:x}", Sha256::digest(&bytes))));
    if let Some(label) = label {
        record.insert("label".into(), json!(label));
    }
    record.insert("features".into(), Value::Object(feature_map));
    Ok(Value::Object(record))
}
