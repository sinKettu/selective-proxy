#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(windows)]
pub use windows::*;

#[cfg(not(any(target_os = "linux", windows)))]
compile_error!("selective-proxy currently supports Linux and Windows only");
