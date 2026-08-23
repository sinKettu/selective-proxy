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
    #[arg(long)]
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
    /// Do not install/remove interception automatically; use install/remove commands manually.
    #[arg(long)]
    manual_setup: bool,
}

impl From<RunArgs> for TrafficConfig {
    fn from(args: RunArgs) -> Self {
        Self {
            port: args.common.port,
            domains: args.domains,
            proxy: args.proxy,
        }
    }
}

fn main() -> Result<()> {
    match Cli::parse().action {
        Action::Install(common) => platform::install(common.port, &common.user),
        Action::Remove => platform::remove(),
        Action::Run(args) => {
            if !args.manual_setup {
                platform::start_supervisor(args.common.port, &args.common.user)?;
            }
            platform::prepare_run_user(&args.common.user)?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(traffic::run(args.into()))
        }
    }
}
