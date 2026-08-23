use std::{
    ffi::CString,
    io::{BufRead, BufReader, Write},
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
    user_id(user, "-u", "uid")
}

fn user_gid(user: &str) -> Result<u32> {
    user_id(user, "-g", "gid")
}

fn user_id(user: &str, argument: &str, kind: &str) -> Result<u32> {
    let output = Command::new("id")
        .args([argument, user])
        .output()
        .context("failed to execute id")?;
    if !output.status.success() {
        bail!("unknown user: {user}");
    }
    String::from_utf8(output.stdout)?
        .trim()
        .parse()
        .with_context(|| format!("invalid {kind} from id"))
}

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("nft setup/removal requires root");
    }
    Ok(())
}

pub fn prepare_run_user(user: &str) -> Result<()> {
    require_root().context("run must be started as root on Linux")?;
    let uid = user_uid(user)?;
    let gid = user_gid(user)?;
    if uid == 0 {
        bail!("--user must name an unprivileged account");
    }
    let user_name = CString::new(user).context("user name contains a NUL byte")?;
    if unsafe { libc::initgroups(user_name.as_ptr(), gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("cannot initialize user groups");
    }
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("cannot drop group privileges");
    }
    if unsafe { libc::setuid(uid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("cannot drop user privileges");
    }
    if unsafe { libc::geteuid() } != uid || unsafe { libc::getegid() } != gid {
        bail!("failed to switch to user {user}");
    }
    eprintln!("relay privileges dropped to {user} (uid {uid}, gid {gid})");
    Ok(())
}

pub fn start_supervisor(port: u16, user: &str) -> Result<()> {
    require_root().context("run must be started as root on Linux")?;
    let executable = std::env::current_exe().context("cannot locate current executable")?;
    let pid = std::process::id().to_string();
    let port = port.to_string();
    let mut child = Command::new(executable)
        .args(["supervise", "--pid", &pid, "--port", &port, "--user", user])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to start privileged lifecycle supervisor")?;
    let stdout = child
        .stdout
        .take()
        .context("supervisor stdout unavailable")?;
    let mut reader = BufReader::new(stdout);
    loop {
        let mut response = String::new();
        let bytes = reader
            .read_line(&mut response)
            .context("cannot read lifecycle supervisor status")?;
        if bytes == 0 {
            let status = child.wait()?;
            bail!("lifecycle supervisor failed to start (status {status})");
        }
        if response.trim() == "READY" {
            break;
        }
        eprint!("supervisor: {response}");
    }
    std::thread::Builder::new()
        .name("nft-supervisor-output".to_owned())
        .spawn(move || {
            for line in reader.lines().map_while(Result::ok) {
                eprintln!("supervisor: {line}");
            }
            let _ = child.wait();
        })
        .context("cannot start lifecycle supervisor output monitor")?;
    eprintln!("automatic nftables lifecycle supervisor started");
    Ok(())
}

pub fn supervise(pid: u32, port: u16, user: &str) -> Result<()> {
    require_root()?;
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as libc::c_int };
    if pidfd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("cannot monitor relay process with pidfd_open");
    }

    let result = supervise_with_pidfd(pidfd, port, user);
    unsafe { libc::close(pidfd) };
    result
}

fn supervise_with_pidfd(pidfd: libc::c_int, port: u16, user: &str) -> Result<()> {
    install_if_needed(port, user)?;
    println!("READY");
    std::io::stdout().flush()?;

    let mut descriptor = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut descriptor, 1, -1) };
        if result > 0 {
            break;
        }
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(std::io::Error::last_os_error()).context("cannot monitor relay process");
        }
    }

    remove_if_present().context("relay exited, but nftables cleanup failed")
}

fn table_exists() -> Result<bool> {
    let status = Command::new("nft")
        .args(["list", "table", "inet", NFT_TABLE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to query nftables table")?;
    Ok(status.success())
}

fn install_if_needed(port: u16, user: &str) -> Result<()> {
    if table_exists()? {
        return Ok(());
    }
    install(port, user)
}

fn remove_if_present() -> Result<()> {
    if !table_exists()? {
        return Ok(());
    }
    remove()
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
