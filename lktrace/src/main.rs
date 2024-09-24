#[macro_use]
extern crate log;

use clap::Parser;
use simplelog::{SimpleLogger, LevelFilter, Config};

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Parse level for trace
    #[arg(short)]
    level: Option<usize>,

    /// Binary trace data file path
    file: Option<String>,
}

fn main() {
    let _ = SimpleLogger::init(LevelFilter::Info, Config::default());

    let cli = Cli::parse();

    info!("level: {:?}, file {:?}", cli.level, cli.file);

    println!("Hello, world!");
    info!("info");
    error!("error");
}
