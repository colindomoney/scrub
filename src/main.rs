mod cli;
mod config;
mod entropy;
mod patterns;
mod redactor;
mod reporter;
mod scanner;

use clap::Parser;
use cli::Cli;
use config::{default_config_path, load_config, ResolvedConfig};
use std::io::{self, Read, Write};
use std::process;

fn main() {
    let cli = Cli::parse();

    // Resolve config file path
    let config_path = cli
        .config
        .clone()
        .or_else(default_config_path);

    let file_config = match config_path {
        Some(ref p) => match load_config(p) {
            Ok(fc) => fc,
            Err(e) => {
                eprintln!("{e}");
                process::exit(1);
            }
        },
        None => config::FileConfig::default(),
    };

    let resolved = match ResolvedConfig::from(&cli, file_config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    // Read input
    let text = match &cli.input_file {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[scrub] error reading {}: {e}", path.display());
                process::exit(1);
            }
        },
        None => {
            let mut buf = String::new();
            if let Err(e) = io::stdin().read_to_string(&mut buf) {
                eprintln!("[scrub] error reading stdin: {e}");
                process::exit(1);
            }
            buf
        }
    };

    let matches = scanner::scan_lines(&text, &resolved);

    // --check takes priority over --dry-run
    if cli.check {
        if cli.verbose {
            reporter::print_verbose_summary(&matches);
        }
        let count = matches.len().min(255) as i32;
        process::exit(count);
    }

    if cli.dry_run {
        if cli.verbose {
            reporter::print_dry_run_summary(&matches);
        }
        // Write original text unchanged
        write_output(&cli, &text);
        return;
    }

    // Normal mode: redact and write
    let output = if matches.is_empty() {
        text.clone()
    } else {
        redactor::redact(&text, &matches)
    };

    if cli.verbose {
        reporter::print_verbose_summary(&matches);
    }

    write_output(&cli, &output);
}

fn write_output(cli: &Cli, content: &str) {
    match &cli.output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, content) {
                eprintln!("[scrub] error writing {}: {e}", path.display());
                process::exit(1);
            }
        }
        None => {
            if let Err(e) = io::stdout().write_all(content.as_bytes()) {
                eprintln!("[scrub] error writing stdout: {e}");
                process::exit(1);
            }
        }
    }
}
