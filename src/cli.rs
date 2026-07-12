use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "scrub", version, about = "Redact secrets and tokens from text")]
pub struct Cli {
    /// Input file (default: stdin)
    pub input_file: Option<PathBuf>,

    /// Detection sensitivity
    #[arg(short = 's', long)]
    pub sensitivity: Option<Sensitivity>,

    /// Input file (alternative to the positional argument)
    #[arg(long, value_name = "FILE", conflicts_with = "input_file")]
    pub input: Option<PathBuf>,

    /// Write output to file instead of stdout
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Config file path
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,

    /// Print redaction summary to stderr
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Show what would be redacted without modifying output
    #[arg(long)]
    pub dry_run: bool,

    /// Check mode: no output, exit 0 if clean, exit N (count) if secrets found
    #[arg(long)]
    pub check: bool,
}

#[derive(Clone, Debug, PartialEq, ValueEnum)]
pub enum Sensitivity {
    Low,
    Medium,
    High,
}
