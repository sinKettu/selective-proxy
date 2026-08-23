mod platform;
mod traffic;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use traffic::TrafficConfig;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand, Debug)]
enum Action {
    /// Install the nftables OUTPUT redirect.
    Install(Common),
    /// Run the transparent relay.
    Run(RunArgs),
    /// Remove the nftables table.
    Remove,
}

#[derive(clap::Args, Debug)]
struct Common {
    #[arg(long, default_value_t = 12345)]
    port: u16,
    /// Account whose traffic bypasses interception; it must own this process and the upstream proxy.
    #[arg(long, default_value = "selective-proxy")]
    user: String,
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    #[command(flatten)]
    common: Common,
    #[arg(long, default_value = "domains.txt")]
    domains: PathBuf,
    /// Upstream proxy URL: http://[user:password@]host:port
    #[arg(long)]
    proxy: String,
}

impl From<RunArgs> for TrafficConfig {
    fn from(args: RunArgs) -> Self {
        Self {
            port: args.common.port,
            user: args.common.user,
            domains: args.domains,
            proxy: args.proxy,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().action {
        Action::Install(common) => platform::install(common.port, &common.user),
        Action::Remove => platform::remove(),
        Action::Run(args) => traffic::run(args.into()).await,
    }
}
