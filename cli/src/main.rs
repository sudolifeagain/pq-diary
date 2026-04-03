use anyhow::Result;
use clap::Parser;

/// pq-diary — post-quantum encrypted CLI journal.
#[derive(Debug, Parser)]
#[command(name = "pq-diary", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Available subcommands. Full command set will be added in TASK-0005.
#[derive(Debug, clap::Subcommand)]
enum Commands {}

fn main() -> Result<()> {
    let _cli = Cli::parse();
    Ok(())
}
