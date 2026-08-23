use std::{
    collections::HashSet,
    fs, io,
    net::{Ipv4Addr, SocketAddr},
    os::fd::AsRawFd,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
    time::timeout,
};
use url::Url;

use crate::system::user_uid;

const SO_ORIGINAL_DST: libc::c_int = 80;
const PEEK_LIMIT: usize = 64 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

pub struct TrafficConfig {
    pub port: u16,
    pub user: String,
    pub domains: PathBuf,
    pub proxy: String,
}

#[derive(Clone, Debug)]
struct Proxy {
    host: String,
    port: u16,
    authorization: Option<String>,
}

impl Proxy {
    fn parse(value: &str) -> Result<Self> {
        let normalized = if value.contains("://") {
            value.to_owned()
        } else {
            format!("http://{value}")
        };
        let url = Url::parse(&normalized).context("invalid proxy URL")?;
        if url.scheme() != "http" {
            bail!("only an http:// upstream proxy is supported");
        }
        let host = url.host_str().context("proxy URL has no host")?.to_owned();
        let port = url.port().unwrap_or(8080);
        let authorization = if url.username().is_empty() {
            None
        } else {
            let credentials = format!("{}:{}", url.username(), url.password().unwrap_or(""));
            Some(format!("Basic {}", BASE64.encode(credentials)))
        };
        Ok(Self {
            host,
            port,
            authorization,
        })
    }
}

#[derive(Debug)]
struct DomainRules {
    path: PathBuf,
    modified: Option<SystemTime>,
    patterns: HashSet<String>,
}

impl DomainRules {
    fn load(path: PathBuf) -> Result<Self> {
        let mut rules = Self {
            path,
            modified: None,
            patterns: HashSet::new(),
        };
        rules.reload()?;
        Ok(rules)
    }

    fn reload(&mut self) -> Result<()> {
        let metadata = fs::metadata(&self.path)
            .with_context(|| format!("cannot stat {}", self.path.display()))?;
        let modified = metadata.modified().ok();
        if self.modified.is_some() && modified == self.modified {
            return Ok(());
        }
        let text = fs::read_to_string(&self.path)
            .with_context(|| format!("cannot read {}", self.path.display()))?;
        self.patterns.clear();
        for line in text.lines() {
            let pattern = line
                .split('#')
                .next()
                .unwrap_or("")
                .trim()
                .trim_end_matches('.')
                .to_lowercase();
            if !pattern.is_empty() {
                self.patterns.insert(pattern);
            }
        }
        self.modified = modified;
        eprintln!(
            "loaded {} domain rules from {}",
            self.patterns.len(),
            self.path.display()
        );
        Ok(())
    }

    fn matches(&mut self, host: Option<&str>) -> bool {
        if let Err(error) = self.reload() {
            eprintln!("WARN   cannot reload rules: {error:#}");
        }
        let Some(host) = host else { return false };
        let host = host.trim_end_matches('.').to_lowercase();
        self.patterns
            .iter()
            .any(|pattern| domain_pattern_matches(pattern, &host))
    }
}

fn domain_pattern_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host.ends_with(&format!(".{suffix}"));
    }
    if !pattern.contains('*') && !pattern.contains('?') {
        return host == pattern || host.ends_with(&format!(".{pattern}"));
    }
    wildcard_match(pattern.as_bytes(), host.as_bytes())
}

fn wildcard_match(pattern: &[u8], value: &[u8]) -> bool {
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            retry += 1;
            v = retry;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn original_destination(stream: &TcpStream) -> io::Result<(Ipv4Addr, u16)> {
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
        return Err(io::Error::last_os_error());
    }
    if address.sin_family != libc::AF_INET as libc::sa_family_t {
        return Err(io::Error::other(format!(
            "unsupported original address family: {}",
            address.sin_family
        )));
    }
    Ok((
        Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
        u16::from_be(address.sin_port),
    ))
}

fn http_host(data: &[u8]) -> Option<String> {
    let headers_end = data.windows(4).position(|part| part == b"\r\n\r\n")?;
    let headers = &data[..headers_end + 2];
    for line in headers.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let (name, value_with_separator) = line.split_at(separator);
        let value = &value_with_separator[1..];
        if name.eq_ignore_ascii_case(b"host") {
            let value = String::from_utf8_lossy(value).trim().to_owned();
            if let Some(rest) = value.strip_prefix('[') {
                return rest.split(']').next().map(ToOwned::to_owned);
            }
            return Some(
                value
                    .rsplit_once(':')
                    .map_or(value.as_str(), |(host, _)| host)
                    .to_lowercase(),
            );
        }
    }
    None
}

fn tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 || data[0] != 22 {
        return None;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let body = data.get(5..5 + record_len)?;
    if body.len() < 4 || body[0] != 1 {
        return None;
    }
    let mut pos = 4 + 2 + 32;
    pos += 1 + *body.get(pos)? as usize;
    let suites = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos += 2 + suites;
    pos += 1 + *body.get(pos)? as usize;
    let extensions_len = u16::from_be_bytes([*body.get(pos)?, *body.get(pos + 1)?]) as usize;
    pos += 2;
    let end = body.len().min(pos + extensions_len);
    while pos + 4 <= end {
        let kind = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        let extension = body.get(pos..pos + len)?;
        pos += len;
        if kind != 0 || extension.len() < 5 || extension[2] != 0 {
            continue;
        }
        let name_len = u16::from_be_bytes([extension[3], extension[4]]) as usize;
        return std::str::from_utf8(extension.get(5..5 + name_len)?)
            .ok()
            .map(str::to_lowercase);
    }
    None
}

async fn read_initial(stream: &mut TcpStream, port: u16) -> Result<(Vec<u8>, Option<String>)> {
    timeout(READ_TIMEOUT, async {
        let mut data = Vec::with_capacity(4096);
        loop {
            if data.len() >= PEEK_LIMIT {
                break;
            }
            let mut chunk = vec![0; 4096.min(PEEK_LIMIT - data.len())];
            let size = stream.read(&mut chunk).await?;
            if size == 0 {
                break;
            }
            data.extend_from_slice(&chunk[..size]);
            let host = if port == 443 {
                tls_sni(&data)
            } else {
                http_host(&data)
            };
            if host.is_some() {
                return Ok((data, host));
            }
            if port == 80 && data.windows(4).any(|part| part == b"\r\n\r\n") {
                break;
            }
            if port == 443 && data.len() >= 5 {
                let length = u16::from_be_bytes([data[3], data[4]]) as usize;
                if data.len() >= 5 + length {
                    break;
                }
            }
        }
        let host = if port == 443 {
            tls_sni(&data)
        } else {
            http_host(&data)
        };
        Ok((data, host))
    })
    .await
    .context("timed out waiting for HTTP Host/TLS SNI")?
}

async fn connect_via_proxy(proxy: &Proxy, host: &str, port: u16) -> Result<TcpStream> {
    let mut stream = timeout(READ_TIMEOUT, TcpStream::connect((&*proxy.host, proxy.port)))
        .await
        .context("proxy connect timed out")??;
    let authority = format!("{host}:{port}");
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n"
    );
    if let Some(value) = &proxy.authorization {
        request.push_str(&format!("Proxy-Authorization: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::with_capacity(1024);
    timeout(READ_TIMEOUT, async {
        while !response.windows(4).any(|part| part == b"\r\n\r\n") {
            if response.len() >= 32 * 1024 {
                bail!("proxy response headers too large");
            }
            let mut chunk = [0_u8; 1024];
            let size = stream.read(&mut chunk).await?;
            if size == 0 {
                bail!("proxy closed before CONNECT response");
            }
            response.extend_from_slice(&chunk[..size]);
        }
        Result::<()>::Ok(())
    })
    .await
    .context("proxy CONNECT response timed out")??;
    let status = response
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let status_text = String::from_utf8_lossy(status).trim().to_owned();
    if !status
        .split(|byte| *byte == b' ')
        .any(|part| part == b"200")
    {
        bail!("proxy CONNECT failed: {status_text}");
    }
    Ok(stream)
}

async fn relay(
    mut client: TcpStream,
    peer: SocketAddr,
    rules: Arc<RwLock<DomainRules>>,
    proxy: Arc<Proxy>,
) -> Result<()> {
    let (destination, port) = original_destination(&client)?;
    let (initial, host) = read_initial(&mut client, port).await?;
    let use_proxy = rules.write().await.matches(host.as_deref());
    let mut upstream = if use_proxy {
        connect_via_proxy(
            &proxy,
            host.as_deref().unwrap_or(&destination.to_string()),
            port,
        )
        .await?
    } else {
        TcpStream::connect((destination, port)).await?
    };
    eprintln!(
        "{:<6} {} -> {}:{}",
        if use_proxy { "PROXY" } else { "DIRECT" },
        peer,
        host.as_deref().unwrap_or("<no-host>"),
        port
    );
    upstream.write_all(&initial).await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

pub async fn run(config: TrafficConfig) -> Result<()> {
    let expected_uid = user_uid(&config.user)?;
    let actual_uid = unsafe { libc::geteuid() };
    if actual_uid == 0 {
        bail!("refusing to run as root; run as --user {}", config.user);
    }
    if actual_uid != expected_uid {
        bail!(
            "run as {}; its traffic is excluded from redirection",
            config.user
        );
    }

    let rules = Arc::new(RwLock::new(DomainRules::load(config.domains)?));
    let proxy = Arc::new(Proxy::parse(&config.proxy)?);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, config.port)).await?;
    eprintln!(
        "listening on 127.0.0.1:{}; press Ctrl-C to stop",
        config.port
    );
    loop {
        let (stream, peer) = listener.accept().await?;
        let (rules, proxy) = (Arc::clone(&rules), Arc::clone(&proxy));
        tokio::spawn(async move {
            if let Err(error) = relay(stream, peer, rules, proxy).await {
                eprintln!("ERROR  {peer}: {error:#}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_host() {
        assert_eq!(
            http_host(b"GET / HTTP/1.1\r\nHost: api.example.com:80\r\n\r\n").as_deref(),
            Some("api.example.com")
        );
    }

    #[test]
    fn matches_domains() {
        assert!(domain_pattern_matches("example.com", "www.example.com"));
        assert!(domain_pattern_matches("*.example.org", "api.example.org"));
        assert!(!domain_pattern_matches("*.example.org", "example.org"));
    }
}
