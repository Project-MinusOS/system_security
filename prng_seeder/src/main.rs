// Copyright (C) 2022 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! FIPS compliant random number conditioner. Reads from /dev/hw_random
//! and applies the NIST SP 800-90A CTR DRBG strategy to provide
//! pseudorandom bytes to clients which connect to a socket provided
//! by init.

mod conditioner;
mod drbg;

use std::{
    convert::Infallible,
    fs::remove_file,
    io::ErrorKind,
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
};

use anyhow::{ensure, Context, Result};
use clap::Parser;
use log::{error, info, LevelFilter};
use nix::sys::signal;
use tokio::{io::AsyncWriteExt, net::UnixListener as TokioUnixListener};

use crate::conditioner::ConditionerBuilder;

// Minimum interval in milliseconds to wait between retries of opening the hwrng source.
const MIN_RETRY_INTERVAL_MS: u64 = 10;

#[derive(Debug, Parser)]
struct Cli {
    #[clap(long, default_value = "/dev/hw_random")]
    source: PathBuf,
    #[clap(long)]
    socket: Option<PathBuf>,
    /// Timeout in milliseconds to wait for the hwrng source to become available.
    ///
    /// Set to 0 to fail immediately if the source is unavailable (try once).
    /// Set to a very large value (e.g. 1 year in ms) to effectively wait indefinitely.
    #[clap(long, default_value = "0")]
    timeout_ms: u64,
    /// Interval in milliseconds to wait between retries.
    ///
    /// If set to a value lower than the minimum (10ms), it will be clamped to the minimum to
    /// prevent busy loops that are causing high CPU usage.
    #[clap(long, default_value = "1000")]
    retry_interval_ms: u64,
}

fn configure_logging() -> Result<()> {
    ensure!(
        logger::init(
            logger::Config::default()
                .with_tag_on_device("prng_seeder")
                .with_max_level(LevelFilter::Info)
        ),
        "log configuration failed"
    );
    Ok(())
}

fn get_socket(path: &Path) -> Result<UnixListener> {
    if let Err(e) = remove_file(path) {
        if e.kind() != ErrorKind::NotFound {
            return Err(e).context(format!("Removing old socket: {}", path.display()));
        }
    } else {
        info!("Deleted old {}", path.display());
    }
    UnixListener::bind(path)
        .with_context(|| format!("In get_socket: binding socket to {}", path.display()))
}

// Retry for a limited time based on the CLI argument
// If it fails after the timeout, we propagate the error so run() can park the thread.
fn wait_for_hwrng(
    source: &Path,
    timeout: std::time::Duration,
    retry_interval: std::time::Duration,
) -> Result<ConditionerBuilder> {
    let start_time = std::time::Instant::now();

    loop {
        match std::fs::File::open(source) {
            Ok(hwrng) => {
                // File opened, try to initialize conditioner
                match ConditionerBuilder::new(hwrng) {
                    Ok(cb) => return Ok(cb),
                    Err(e) => {
                        if start_time.elapsed() > timeout {
                            return Err(e).context("Timed out initializing conditioner");
                        }
                        info!("Conditioner init failed: {e}. Retrying...");
                    }
                }
            }
            Err(e) => {
                if start_time.elapsed() > timeout {
                    return Err(e).context(format!("Timed out opening hwrng {}", source.display()));
                }
                info!("Unable to open hwrng {}: {e}. Retrying...", source.display());
            }
        }
        std::thread::sleep(retry_interval);
    }
}

fn setup() -> Result<(ConditionerBuilder, UnixListener)> {
    configure_logging()?;
    let cli = Cli::try_parse()?;
    // Enforce minimum retry interval to prevent busy loops
    let retry_interval_ms = if cli.retry_interval_ms < MIN_RETRY_INTERVAL_MS {
        info!(
            "retry_interval_ms {} is too small, using minimum {}ms",
            cli.retry_interval_ms, MIN_RETRY_INTERVAL_MS
        );
        MIN_RETRY_INTERVAL_MS
    } else {
        cli.retry_interval_ms
    };
    // SAFETY: nobody has taken ownership of the inherited FDs yet.
    unsafe { rustutils::inherited_fd::init_once() }
        .context("In setup, failed to own inherited FDs")?;
    // SAFETY: Nothing else sets the signal handler, so either it was set here or it is the default.
    unsafe { signal::signal(signal::Signal::SIGPIPE, signal::SigHandler::SigIgn) }
        .context("In setup, setting SIGPIPE to SIG_IGN")?;

    let listener = match cli.socket {
        Some(path) => get_socket(path.as_path())?,
        None => rustutils::android::sockets::android_get_control_socket("prng_seeder")
            .context("In setup, calling android_get_control_socket")?
            .into(),
    };
    let timeout = std::time::Duration::from_millis(cli.timeout_ms);
    let retry_interval = std::time::Duration::from_millis(retry_interval_ms);
    let conditioner_builder = wait_for_hwrng(&cli.source, timeout, retry_interval)?;

    Ok((conditioner_builder, listener))
}

async fn listen_loop(cb: ConditionerBuilder, listener: UnixListener) -> Result<Infallible> {
    let mut conditioner = cb.build();
    listener.set_nonblocking(true).context("In listen_loop, on set_nonblocking")?;
    let listener = TokioUnixListener::from_std(listener).context("In listen_loop, on from_std")?;
    info!("Starting listen loop");
    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let new_bytes = conditioner.request()?;
                tokio::spawn(async move {
                    if let Err(e) = stream.write_all(&new_bytes).await {
                        error!("Request failed: {e}");
                    }
                });
                conditioner.reseed_if_necessary().await?;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e).context("accept on socket failed"),
        }
    }
}

fn run() -> Result<Infallible> {
    let (cb, listener) = match setup() {
        Ok(t) => t,
        Err(e) => {
            // If setup fails, just hang forever. That way init doesn't respawn us.
            error!("Hanging forever because setup failed: {e:?}");
            // Logs are sometimes mysteriously not being logged, so print too
            println!("prng_seeder: Hanging forever because setup failed: {e:?}");
            loop {
                std::thread::park();
                error!("std::thread::park() finished unexpectedly, re-parking thread");
            }
        }
    };

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("In run, building reactor")?
        .block_on(async { listen_loop(cb, listener).await })
}

fn main() {
    let e = run();
    error!("Launch terminated: {e:?}");
    // Logs are sometimes mysteriously not being logged, so print too
    println!("prng_seeder: launch terminated: {e:?}");
    std::process::exit(-1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use std::io::Write;
    use std::time::Duration;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_wait_for_hwrng_success() {
        // Create a temporary file to simulate /dev/hw_random
        let file_path = PathBuf::from("temp_test_hwrng_success");
        {
            let mut file = std::fs::File::create(&file_path).unwrap();
            // Write 192 bytes (RAW_ENTROPY_SAMPLE_LEN) so ConditionerBuilder::new succeeds
            file.write_all(&[0u8; 192]).unwrap();
        }

        let result = wait_for_hwrng(&file_path, Duration::from_secs(1), Duration::from_millis(100));
        let _ = std::fs::remove_file(&file_path);

        assert!(result.is_ok(), "Should succeed when file exists and has data");
    }

    #[test]
    fn test_wait_for_hwrng_timeout_missing_file() {
        let file_path = PathBuf::from("temp_test_hwrng_missing");
        // Ensure it doesn't exist
        let _ = std::fs::remove_file(&file_path);

        let start = std::time::Instant::now();
        let timeout = Duration::from_millis(1000);

        let result = wait_for_hwrng(&file_path, timeout, Duration::from_millis(100));

        assert!(result.is_err(), "Should fail when file is missing");
        assert!(start.elapsed() >= timeout, "Should wait at least for the timeout duration");
    }

    #[test]
    fn test_wait_for_hwrng_timeout_empty_file() {
        // Create an empty file. ConditionerBuilder needs 192 bytes, so this will fail initialization.
        let file_path = PathBuf::from("temp_test_hwrng_empty");
        std::fs::File::create(&file_path).unwrap();

        let result =
            wait_for_hwrng(&file_path, Duration::from_millis(100), Duration::from_millis(10));

        let _ = std::fs::remove_file(&file_path);

        assert!(result.is_err(), "Should fail when file is empty (Conditioner init failure)");
    }

    #[test]
    fn test_wait_for_hwrng_retry_success() {
        let file_path = PathBuf::from("temp_test_hwrng_retry");
        // Ensure it doesn't exist initially
        let _ = std::fs::remove_file(&file_path);

        // Spawn a thread to create the file after a delay
        let file_path_clone = file_path.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1000));
            let mut file =
                std::fs::File::create(&file_path_clone).expect("Failed to create temp file");
            // Write enough data for ConditionerBuilder (192 bytes)
            file.write_all(&[0u8; 192]).expect("Failed to write to temp file");
        });

        // Wait with a timeout longer than the delay (5000ms > 1000ms)
        let result =
            wait_for_hwrng(&file_path, Duration::from_millis(5000), Duration::from_millis(100));

        let _ = std::fs::remove_file(&file_path);

        assert!(result.is_ok(), "Should succeed after retrying until file appears");
    }

    #[test]
    fn test_wait_for_hwrng_zero_timeout() {
        let file_path = PathBuf::from("temp_test_hwrng_zero_timeout");
        // Ensure file does not exist initially
        let _ = std::fs::remove_file(&file_path);

        let start = std::time::Instant::now();

        // Use a large retry interval (1s) to prove that if it fails, it returns immediately
        // and doesn't sleep.
        let result = wait_for_hwrng(&file_path, Duration::ZERO, Duration::from_secs(1));

        assert!(result.is_err(), "Should fail immediately if file is missing and timeout is 0");

        // If it slept, the elapsed time would be > 1s.
        assert!(start.elapsed() < Duration::from_secs(1), "Should not sleep if timeout is 0");
    }
}
