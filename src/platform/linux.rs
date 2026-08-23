use std::{
    ffi::CString,
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
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
    let parent_pid = std::process::id();
    let mut pipe = [0; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error()).context("cannot create supervisor pipe");
    }
    let read_fd = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    let write_fd = unsafe { OwnedFd::from_raw_fd(pipe[1]) };

    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(std::io::Error::last_os_error()).context("cannot fork lifecycle supervisor");
    }
    if child_pid == 0 {
        drop(read_fd);
        let exit_code = match supervise(parent_pid, port, user, write_fd) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("lifecycle supervisor failed: {error:#}");
                1
            }
        };
        unsafe { libc::_exit(exit_code) };
    }

    drop(write_fd);
    let mut status = [0_u8; 1];
    let read_result = unsafe { libc::read(read_fd.as_raw_fd(), status.as_mut_ptr().cast(), 1) };
    if read_result != 1 || status[0] != 1 {
        let mut wait_status = 0;
        unsafe { libc::waitpid(child_pid, &mut wait_status, 0) };
        bail!("lifecycle supervisor failed to start");
    }
    eprintln!("automatic nftables lifecycle supervisor started");
    Ok(())
}

fn supervise(pid: u32, port: u16, user: &str, ready: OwnedFd) -> Result<()> {
    require_root()?;
    if unsafe { libc::setsid() } < 0 {
        return Err(std::io::Error::last_os_error())
            .context("cannot create lifecycle supervisor session");
    }
    ignore_cleanup_signals()?;
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as libc::c_int };
    if pidfd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("cannot monitor relay process with pidfd_open");
    }

    let result = supervise_with_pidfd(pidfd, port, user, ready);
    unsafe { libc::close(pidfd) };
    result
}

fn ignore_cleanup_signals() -> Result<()> {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        if unsafe { libc::signal(signal, libc::SIG_IGN) } == libc::SIG_ERR {
            return Err(std::io::Error::last_os_error())
                .context("cannot isolate lifecycle supervisor signals");
        }
    }
    Ok(())
}

fn supervise_with_pidfd(pidfd: libc::c_int, port: u16, user: &str, ready: OwnedFd) -> Result<()> {
    install_if_needed(port, user)?;
    let ready_byte = [1_u8];
    if unsafe { libc::write(ready.as_raw_fd(), ready_byte.as_ptr().cast(), 1) } != 1 {
        return Err(std::io::Error::last_os_error()).context("cannot notify relay about readiness");
    }
    // The readiness pipe is startup-only. Closing it ensures the supervisor
    // has no long-lived communication dependency on the relay process.
    drop(ready);

    let mut descriptor = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let monitor_result = loop {
        let result = unsafe { libc::poll(&mut descriptor, 1, -1) };
        if result > 0 {
            break Ok(());
        }
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            break Err(std::io::Error::last_os_error()).context("cannot monitor relay process");
        }
    };

    let cleanup_result = remove_if_present().context("nftables cleanup failed");
    match (monitor_result, cleanup_result) {
        (_, Err(cleanup_error)) => Err(cleanup_error),
        (Err(monitor_error), Ok(())) => Err(monitor_error),
        (Ok(()), Ok(())) => {
            eprintln!("nftables cleanup completed after relay exit");
            Ok(())
        }
    }
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
