# Selective HTTP/HTTPS proxy PoC for Linux and Windows (Rust)

The project demonstrates system-wide selective proxying, inspection of the
HTTP `Host` header or TLS ClientHello SNI, and an HTTP `CONNECT` upstream
proxy. Linux uses an nftables `OUTPUT` redirect. Windows uses WinDivert and an
in-memory client-port-to-original-destination table.

The previous Python implementation remains in [`selective_proxy.py`](selective_proxy.py)
as a readable reference. The Rust binary is the primary implementation.

## Requirements and limitations

- Linux requires nftables. Windows requires WinDivert 2.x and administrator
  privileges.
- IPv4 TCP traffic on destination ports 80 and 443 only.
- TLS routing uses visible SNI. Encrypted Client Hello (ECH) cannot be routed by
  domain and therefore goes direct.
- QUIC/HTTP3 uses UDP and is not intercepted. Browsers normally fall back to
  TCP, but UDP/443 can be blocked separately if deterministic fallback is
  required.
- Domain decisions apply to new connections. Editing
  [`domains.txt`](domains.txt) is detected automatically.
- This is a learning PoC, not a hardened security or leak-prevention boundary.
  Use a network namespace or a mature transparent proxy for production.

## Setup

### Linux

Build the optimized binary:

```bash
cargo build --release
```

Each compiled binary embeds the package version from `Cargo.toml`, UTC build
date and time, Git commit hash, latest commit message, profile, and target.
Display the full information through either command:

```bash
./target/release/selective-proxy --version
./target/release/selective-proxy --help
```

The resulting executable is `./target/release/selective-proxy`.

Create a dedicated unprivileged account. Its traffic is excluded from the
nftables redirect so that connections created by the PoC do not loop back into
it:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin selective-proxy
```

Start `run` as root and pass the required unprivileged account in `--user`.
The root launcher starts a small privileged supervisor and then permanently
drops the relay process UID, GID, and supplementary groups to that account.
The supervisor installs the nftables table if needed, monitors the relay
through a Linux pidfd, and removes the table after the relay exits, including
termination by `kill -9`. The proxy can be an IP address or a hostname:

```bash
sudo ./target/release/selective-proxy run \
  --domains ./domains.txt \
  --proxy http://127.0.0.1:8080 \
  --user selective-proxy \
  --port 12345
```

To retain the old manual nftables setup mode, pass `--manual-setup` to `run`,
install rules in another terminal, and remove them manually afterward. The
`run` command itself is still started as root so it can switch to `--user`:

```bash
sudo ./target/release/selective-proxy install --user selective-proxy --port 12345
```

Test both paths:

```bash
curl -v https://example.com/
curl -v https://example.net/
```

The listener prints `PROXY` or `DIRECT` for each recognized connection.

With `--manual-setup`, remove interception before stopping the listener:

```bash
sudo ./target/release/selective-proxy remove
```

Basic proxy authentication is accepted in the URL:

```bash
--proxy http://username:password@proxy.example:3128
```

Credentials are visible in the process command line, so this syntax is only
suitable for a PoC.

## Safety notes

Installing the rules before the listener starts makes new HTTP(S) connections
fail until it is running. Always keep the removal command available. nftables
rules are not persisted by this PoC and normally disappear after reboot.

Traffic owned by the dedicated service UID bypasses interception. Do not run
untrusted applications under that account. Localhost and `0.0.0.0/8` are also
excluded. Other private or link-local destinations are intercepted unless
their domain does not match, in which case the PoC reconnects directly.

### Windows

Download WinDivert 2.x and place the matching `WinDivert.dll` and driver file
(`WinDivert64.sys` for a 64-bit build) next to `selective-proxy.exe`. Build and
run from an elevated terminal:

```powershell
cargo build --release
.\target\release\selective-proxy.exe run `
  --domains .\domains.txt `
  --proxy http://127.0.0.1:8080 `
  --port 12345
```

The Windows filter exists only while the process is running; `install` and
`remove` are informational compatibility commands. The relay reserves each of
its outbound source ports in a bypass table to prevent recursive interception.
The current Windows implementation handles IPv4 TCP ports 80 and 443 only.
