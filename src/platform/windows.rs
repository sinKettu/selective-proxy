use std::{
    collections::{HashMap, HashSet},
    ffi::{c_char, c_void},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
};

use anyhow::{Context, Result, bail};
use libloading::Library;
use tokio::net::{TcpSocket, TcpStream};

type Handle = *mut c_void;
type OpenFn = unsafe extern "system" fn(*const c_char, u32, i16, u64) -> Handle;
type RecvFn =
    unsafe extern "system" fn(Handle, *mut c_void, u32, *mut u32, *mut WinDivertAddress) -> i32;
type SendFn =
    unsafe extern "system" fn(Handle, *const c_void, u32, *mut u32, *const WinDivertAddress) -> i32;
type ChecksumFn = unsafe extern "system" fn(*mut c_void, u32, *mut WinDivertAddress, u64) -> i32;
type CloseFn = unsafe extern "system" fn(Handle) -> i32;

#[repr(C, align(8))]
struct WinDivertAddress([u8; 80]);

const ADDRESS_FLAGS_OFFSET: usize = 8;
const ADDRESS_OUTBOUND: u32 = 1 << 17;
const ADDRESS_LOOPBACK: u32 = 1 << 18;

impl WinDivertAddress {
    fn flags(&self) -> u32 {
        u32::from_ne_bytes(
            self.0[ADDRESS_FLAGS_OFFSET..ADDRESS_FLAGS_OFFSET + 4]
                .try_into()
                .expect("WinDivert address flags have a fixed size"),
        )
    }

    fn set_inbound(&mut self, loopback: bool) {
        let mut flags = self.flags() & !ADDRESS_OUTBOUND;
        if loopback {
            flags |= ADDRESS_LOOPBACK;
        } else {
            flags &= !ADDRESS_LOOPBACK;
        }
        self.0[ADDRESS_FLAGS_OFFSET..ADDRESS_FLAGS_OFFSET + 4]
            .copy_from_slice(&flags.to_ne_bytes());
    }

    fn is_outbound(&self) -> bool {
        self.flags() & ADDRESS_OUTBOUND != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Rewrite {
    Unchanged,
    ToRelay,
    FromRelay,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Client {
    address: Ipv4Addr,
    port: u16,
}

struct State {
    destinations: Mutex<HashMap<Client, (Ipv4Addr, u16)>>,
    bypass_ports: Mutex<HashSet<u16>>,
    redirected_packets: AtomicUsize,
    reverse_packets: AtomicUsize,
    bypassed_packets: AtomicUsize,
}

pub struct Runtime {
    state: Arc<State>,
}

pub struct ConnectionGuard {
    state: Arc<State>,
    port: u16,
}

pub fn listener_address() -> Ipv4Addr {
    Ipv4Addr::UNSPECIFIED
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Ok(mut ports) = self.state.bypass_ports.lock() {
            ports.remove(&self.port);
            eprintln!("WINDIVERT bypass DROP local_port={}", self.port);
        }
    }
}

impl Runtime {
    pub fn start(port: u16) -> Result<Self> {
        let state = Arc::new(State {
            destinations: Mutex::new(HashMap::new()),
            bypass_ports: Mutex::new(HashSet::new()),
            redirected_packets: AtomicUsize::new(0),
            reverse_packets: AtomicUsize::new(0),
            bypassed_packets: AtomicUsize::new(0),
        });
        let worker_state = Arc::clone(&state);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("windivert-redirect".to_owned())
            .spawn(move || divert_loop(port, worker_state, ready_tx))
            .context("cannot start WinDivert worker")?;
        ready_rx
            .recv()
            .context("WinDivert worker stopped during startup")??;
        Ok(Self { state })
    }

    pub fn original_destination(
        &self,
        _stream: &TcpStream,
        peer: SocketAddr,
    ) -> Result<(Ipv4Addr, u16)> {
        let IpAddr::V4(address) = peer.ip() else {
            bail!("WinDivert relay currently supports IPv4 clients only");
        };
        let destination = self
            .state
            .destinations
            .lock()
            .map_err(|_| anyhow::anyhow!("WinDivert destination table is poisoned"))?
            .get(&Client {
                address,
                port: peer.port(),
            })
            .copied();
        match destination {
            Some(destination) => {
                eprintln!(
                    "WINDIVERT lookup HIT  peer={peer} original={}:{}",
                    destination.0, destination.1
                );
                Ok(destination)
            }
            None => {
                let entries = self
                    .state
                    .destinations
                    .lock()
                    .map(|table| table.len())
                    .unwrap_or_default();
                eprintln!("WINDIVERT lookup MISS peer={peer} table_entries={entries}");
                bail!("original destination is absent from WinDivert table")
            }
        }
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<(TcpStream, ConnectionGuard)> {
        let address = tokio::net::lookup_host((host, port))
            .await?
            .find(SocketAddr::is_ipv4)
            .context("upstream host has no IPv4 address")?;
        let socket = TcpSocket::new_v4()?;
        socket.bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))?;
        let port = socket.local_addr()?.port();
        self.state
            .bypass_ports
            .lock()
            .map_err(|_| anyhow::anyhow!("WinDivert bypass table is poisoned"))?
            .insert(port);
        eprintln!("WINDIVERT bypass ADD  local_port={port} upstream={address}");
        let guard = ConnectionGuard {
            state: Arc::clone(&self.state),
            port,
        };
        let stream = socket.connect(address).await?;
        Ok((stream, guard))
    }
}

pub fn prepare_run_user(_user: &str) -> Result<()> {
    Ok(())
}

pub fn start_supervisor(_port: u16, _user: &str) -> Result<()> {
    Ok(())
}

pub fn install(_port: u16, _user: &str) -> Result<()> {
    println!(
        "Windows interception is installed dynamically by `run`; place WinDivert.dll and the matching WinDivert driver next to the executable"
    );
    Ok(())
}

pub fn remove() -> Result<()> {
    println!("WinDivert filters are removed automatically when the process exits");
    Ok(())
}

struct Api {
    _library: Library,
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    checksum: ChecksumFn,
    close: CloseFn,
}

impl Api {
    unsafe fn load() -> Result<Self> {
        let library =
            unsafe { Library::new("WinDivert.dll") }.context("cannot load WinDivert.dll")?;
        let open = unsafe { *library.get(b"WinDivertOpen\0")? };
        let recv = unsafe { *library.get(b"WinDivertRecv\0")? };
        let send = unsafe { *library.get(b"WinDivertSend\0")? };
        let checksum = unsafe { *library.get(b"WinDivertHelperCalcChecksums\0")? };
        let close = unsafe { *library.get(b"WinDivertClose\0")? };
        Ok(Self {
            _library: library,
            open,
            recv,
            send,
            checksum,
            close,
        })
    }
}

fn divert_loop(port: u16, state: Arc<State>, ready: mpsc::SyncSender<Result<()>>) {
    if let Err(error) = divert_loop_inner(port, state, &ready) {
        let _ = ready.send(Err(error));
    }
}

fn divert_loop_inner(
    port: u16,
    state: Arc<State>,
    ready: &mpsc::SyncSender<Result<()>>,
) -> Result<()> {
    let api = unsafe { Api::load()? };
    let filter = format!(
        "outbound and ip and tcp and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.SrcPort == {port})\0"
    );
    let handle = unsafe { (api.open)(filter.as_ptr().cast(), 0, 0, 0) };
    if handle.is_null() || handle as isize == -1 {
        bail!(
            "WinDivertOpen failed (Windows error {}); run elevated and verify the driver files",
            std::io::Error::last_os_error()
        );
    }
    ready.send(Ok(())).ok();
    eprintln!("WINDIVERT filter active: relay_port={port}, IPv4 TCP 80/443");

    let mut packet = vec![0_u8; 65_535];
    loop {
        let mut packet_len = 0_u32;
        let mut address = WinDivertAddress([0; 80]);
        let received = unsafe {
            (api.recv)(
                handle,
                packet.as_mut_ptr().cast(),
                packet.len() as u32,
                &mut packet_len,
                &mut address,
            )
        };
        if received == 0 {
            unsafe { (api.close)(handle) };
            bail!("WinDivertRecv failed: {}", std::io::Error::last_os_error());
        }
        let bytes = &mut packet[..packet_len as usize];
        let rewrite = rewrite_packet(bytes, port, &state)?;
        match rewrite {
            Rewrite::ToRelay => address.set_inbound(false),
            Rewrite::FromRelay => address.set_inbound(false),
            Rewrite::Unchanged => {}
        }
        if rewrite != Rewrite::Unchanged && address.is_outbound() {
            unsafe { (api.close)(handle) };
            bail!("failed to switch rewritten WinDivert packet to inbound");
        }
        unsafe {
            (api.checksum)(bytes.as_mut_ptr().cast(), packet_len, &mut address, 0);
        }
        let mut sent = 0;
        if unsafe {
            (api.send)(
                handle,
                bytes.as_ptr().cast(),
                packet_len,
                &mut sent,
                &address,
            )
        } == 0
        {
            unsafe { (api.close)(handle) };
            bail!("WinDivertSend failed: {}", std::io::Error::last_os_error());
        }
    }
}

fn rewrite_packet(packet: &mut [u8], relay_port: u16, state: &State) -> Result<Rewrite> {
    if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return Ok(Rewrite::Unchanged);
    }
    let ip_len = usize::from(packet[0] & 0x0f) * 4;
    if ip_len < 20 || packet.len() < ip_len + 20 {
        return Ok(Rewrite::Unchanged);
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let source_port = u16::from_be_bytes([packet[ip_len], packet[ip_len + 1]]);
    let destination_port = u16::from_be_bytes([packet[ip_len + 2], packet[ip_len + 3]]);

    if source_port == relay_port {
        let client = Client {
            address: destination,
            port: destination_port,
        };
        if let Some((original_address, original_port)) = state
            .destinations
            .lock()
            .map_err(|_| anyhow::anyhow!("WinDivert destination table is poisoned"))?
            .get(&client)
            .copied()
        {
            let count = state.reverse_packets.fetch_add(1, Ordering::Relaxed) + 1;
            if count <= 20 {
                eprintln!(
                    "WINDIVERT reverse #{count}: {source}:{source_port} -> {destination}:{destination_port}; spoof source={original_address}:{original_port}"
                );
            }
            packet[12..16].copy_from_slice(&original_address.octets());
            packet[ip_len..ip_len + 2].copy_from_slice(&original_port.to_be_bytes());
            return Ok(Rewrite::FromRelay);
        }
        return Ok(Rewrite::Unchanged);
    }

    if state
        .bypass_ports
        .lock()
        .map_err(|_| anyhow::anyhow!("WinDivert bypass table is poisoned"))?
        .contains(&source_port)
    {
        let count = state.bypassed_packets.fetch_add(1, Ordering::Relaxed) + 1;
        if count <= 20 {
            eprintln!(
                "WINDIVERT bypass #{count}: {source}:{source_port} -> {destination}:{destination_port}"
            );
        }
        return Ok(Rewrite::Unchanged);
    }

    if destination_port == 80 || destination_port == 443 {
        let count = state.redirected_packets.fetch_add(1, Ordering::Relaxed) + 1;
        if count <= 20 {
            let tcp_flags = packet[ip_len + 13];
            eprintln!(
                "WINDIVERT redirect #{count}: {source}:{source_port} -> {destination}:{destination_port}; relay={source}:{relay_port}; tcp_flags=0x{tcp_flags:02x}"
            );
        }
        state
            .destinations
            .lock()
            .map_err(|_| anyhow::anyhow!("WinDivert destination table is poisoned"))?
            .insert(
                Client {
                    address: source,
                    port: source_port,
                },
                (destination, destination_port),
            );
        // Keep both endpoints on the same real local interface. Windows does
        // not reliably deliver LAN-source -> 127.0.0.1 packets to TCP even
        // when WinDivert reinjects them as inbound loopback traffic.
        packet[16..20].copy_from_slice(&source.octets());
        packet[ip_len + 2..ip_len + 4].copy_from_slice(&relay_port.to_be_bytes());
        return Ok(Rewrite::ToRelay);
    }
    Ok(Rewrite::Unchanged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windivert_address_abi_and_direction_bits() {
        assert_eq!(size_of::<WinDivertAddress>(), 80);
        assert_eq!(align_of::<WinDivertAddress>(), 8);

        let mut address = WinDivertAddress([0; 80]);
        address.0[ADDRESS_FLAGS_OFFSET..ADDRESS_FLAGS_OFFSET + 4]
            .copy_from_slice(&(ADDRESS_OUTBOUND | ADDRESS_LOOPBACK).to_ne_bytes());
        assert!(address.is_outbound());

        address.set_inbound(false);
        assert!(!address.is_outbound());
        assert_eq!(address.flags() & ADDRESS_LOOPBACK, 0);

        address.set_inbound(true);
        assert!(!address.is_outbound());
        assert_ne!(address.flags() & ADDRESS_LOOPBACK, 0);
    }
}
