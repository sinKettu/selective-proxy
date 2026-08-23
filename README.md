# Selective HTTP/HTTPS proxy PoC for Linux (Rust)

[`src/main.rs`](src/main.rs) demonstrates system-wide selective
proxying with an nftables `OUTPUT` redirect, inspection of the HTTP `Host`
header or TLS ClientHello SNI, and an HTTP `CONNECT` upstream proxy.

The previous Python implementation remains in [`selective_proxy.py`](selective_proxy.py)
as a readable reference. The Rust binary is the primary implementation.

## Requirements and limitations

- Linux, Rust/Cargo for building, a C linker (`build-essential` on Ubuntu), and nftables.
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

Build the optimized binary:

```bash
cargo build --release
```

The resulting executable is `./target/release/selective-proxy`.

Create a dedicated unprivileged account. Its traffic is excluded from the
nftables redirect so that connections created by the PoC do not loop back into
it:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin selective-proxy
```

Start the listener as that account. The proxy can be an IP address or a
hostname; resolve it before installing interception rules if the local resolver
itself depends on intercepted HTTP(S):

```bash
sudo -u selective-proxy ./target/release/selective-proxy run \
  --domains ./domains.txt \
  --proxy http://127.0.0.1:8080 \
  --user selective-proxy \
  --port 12345
```

In another terminal, install the nftables rules:

```bash
sudo ./target/release/selective-proxy install --user selective-proxy --port 12345
```

Test both paths:

```bash
curl -v https://example.com/
curl -v https://example.net/
```

The listener prints `PROXY` or `DIRECT` for each recognized connection.

Remove interception before stopping the listener:

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
