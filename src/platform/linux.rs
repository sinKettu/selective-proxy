use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    os::fd::AsRawFd,
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};
use tokio::net::TcpStream;

const NFT_TABLE: &str = "selective_proxy_poc";
const SO_ORIGINAL_DST: libc::c_int = 80;

pub struct Runtime;

pub struct ConnectionGuard;

pub fn listener_address() -> Ipv4Addr {
    Ipv4Addr::LOCALHOST
}

impl Runtime {
    pub fn start(_port: u16) -> Result<Self> {
        Ok(Self)
    }

    pub fn original_destination(
        &self,
        stream: &TcpStream,
        _peer: SocketAddr,
    ) -> Result<(Ipv4Addr, u16)> {
        let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut length = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                (&mut address as *mut libc::sockaddr_in).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if address.sin_family != libc::AF_INET as libc::sa_family_t {
            bail!(
                "unsupported original address family: {}",
                address.sin_family
            );
        }
        Ok((
            Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
            u16::from_be(address.sin_port),
        ))
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<(TcpStream, ConnectionGuard)> {
        Ok((TcpStream::connect((host, port)).await?, ConnectionGuard))
    }
}

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

pub fn verify_run_user(user: &str) -> Result<()> {
    let expected_uid = user_uid(user)?;
    let actual_uid = unsafe { libc::geteuid() };
    if actual_uid == 0 {
        bail!("refusing to run as root; run as --user {user}");
    }
    if actual_uid != expected_uid {
        bail!("run as {user}; its traffic is excluded from redirection");
    }
    Ok(())
}

pub fn install(port: u16, user: &str) -> Result<()> {
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

pub fn remove() -> Result<()> {
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
