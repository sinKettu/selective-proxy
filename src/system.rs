use std::{
    io::Write,
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};

const NFT_TABLE: &str = "selective_proxy_poc";

pub(crate) fn user_uid(user: &str) -> Result<u32> {
    let output = Command::new("id")
        .args(["-u", user])
        .output()
        .context("failed to execute id")?;
    if !output.status.success() {
        bail!("unknown user: {user}");
    }
    String::from_utf8(output.stdout)?
        .trim()
        .parse()
        .context("invalid uid from id")
}

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("nft setup/removal requires root");
    }
    Ok(())
}

pub fn install_nft(port: u16, user: &str) -> Result<()> {
    require_root()?;
    let uid = user_uid(user)?;
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", NFT_TABLE])
        .stderr(Stdio::null())
        .status();
    let script = format!(
        "add table inet {NFT_TABLE}\n\
         add chain inet {NFT_TABLE} output {{ type nat hook output priority dstnat; policy accept; }}\n\
         add rule inet {NFT_TABLE} output meta skuid {uid} return\n\
         add rule inet {NFT_TABLE} output ip daddr 127.0.0.0/8 return\n\
         add rule inet {NFT_TABLE} output ip daddr 0.0.0.0/8 return\n\
         add rule inet {NFT_TABLE} output tcp dport {{ 80, 443 }} redirect to :{port}\n"
    );
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .context("nft stdin unavailable")?
        .write_all(script.as_bytes())?;
    if !child.wait()?.success() {
        bail!("failed to install nftables rules");
    }
    println!("nftables rules installed; excluded service user is {user} (uid {uid})");
    Ok(())
}

pub fn remove_nft() -> Result<()> {
    require_root()?;
    let status = Command::new("nft")
        .args(["delete", "table", "inet", NFT_TABLE])
        .status()?;
    if !status.success() {
        bail!("failed to remove nftables table");
    }
    println!("nftables rules removed");
    Ok(())
}
