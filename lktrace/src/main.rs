#[macro_use]
extern crate log;

use std::io::Result;
use clap::Parser;
use simplelog::{SimpleLogger, LevelFilter, Config};

mod level0;
mod level1;
mod level2;
mod event;
mod sysno;
mod errno;
mod mmap;
mod signal;
mod payload;

const IN: u64 = 0;
const OUT: u64 = 1;

const DEFAULT_LEVEL: usize = 1;
const DEFAULT_DATA_FILE: &str = "./lk_trace.data";

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Parse level for trace.
    /// 0: Raw output;
    /// 1 (default): group trace events by thead;
    /// 2: replace ids with seq-names
    #[arg(short)]
    level: Option<usize>,

    /// Binary trace data file path
    file: Option<String>,
}

fn main() {
    let log_level = std::env::var("LOG").unwrap_or(String::from("err"));
    println!("level: {}", log_level);

    let log_filter = match log_level.as_str() {
        "err" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        _ => LevelFilter::Error,
    };

    let _ = SimpleLogger::init(log_filter, Config::default());

    let cli = Cli::parse();

    let level = cli.level.unwrap_or(DEFAULT_LEVEL);
    let path = cli.file.unwrap_or(DEFAULT_DATA_FILE.to_owned());
    info!("Level: {}, Data: {}", level, path);

    if let Err(e) = analyse(&path, level) {
        error!("analyse {} failed {}", path, e);
    }
}

fn analyse(path: &str, level: usize) -> Result<()> {
    match level {
        0 => level0::analyse(path),
        1 => level1::analyse(path),
        2 => level2::analyse(path),
        _ => panic!("bad level {}", level),
    }
}
