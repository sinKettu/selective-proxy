use std::{
    env,
    error::Error,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() -> Result<(), Box<dyn Error>> {
    let built_at = Command::new("date")
        .args(["-u", "+%Y-%m-%d %H:%M:%S UTC"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| {
            let seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!("Unix timestamp {seconds}")
        });
    let git_hash =
        git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "not-a-git-build".to_owned());
    let commit_message = git(&["log", "-1", "--pretty=%s"])
        .unwrap_or_else(|| "commit message unavailable".to_owned())
        .replace(['\r', '\n'], " ");
    let package_version = env::var("CARGO_PKG_VERSION")?;
    let profile = env::var("PROFILE").unwrap_or_else(|_| "unknown".to_owned());
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=SELECTIVE_PROXY_BUILD_VERSION={package_version}");
    println!("cargo:rustc-env=SELECTIVE_PROXY_BUILD_TIME={built_at}");
    println!("cargo:rustc-env=SELECTIVE_PROXY_GIT_HASH={git_hash}");
    println!("cargo:rustc-env=SELECTIVE_PROXY_GIT_MESSAGE={commit_message}");
    println!("cargo:rustc-env=SELECTIVE_PROXY_BUILD_PROFILE={profile}");
    println!("cargo:rustc-env=SELECTIVE_PROXY_BUILD_TARGET={target}");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
