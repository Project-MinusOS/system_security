// Copyright (C) 2025 The Android Open Source Project
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

//! Test client for `prng_seeder`.
//!
//! Connects to UNIX domain socket at `/dev/socket/prng_seeder` (by default)
//! and reads random data.

use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, info, LevelFilter};
use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
use std::collections::HashSet;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

/// Amount of entropy to read. Set to match the value of `DAEMON_RESPONSE_LEN` in
/// `external/boringssl/src/crypto/rand/passive.cc`, which matches the value of
/// `SEED_FOR_CLIENT_LEN` in `prng_seeder/src/conditioner.rs`.
const DATA_LEN: usize = 496;

#[derive(Debug, Parser)]
struct Options {
    /// Unix domain socket to connect to.
    #[clap(long, default_value = "/dev/socket/prng_seeder")]
    socket: PathBuf,
    /// Number of parallel test threads to run.
    #[clap(long, default_value = "1")]
    threads: usize,
    /// Number of randomness retrieval operations to perform.
    #[clap(long, default_value = "1")]
    iterations: usize,
    /// Log to Android logger; if not set, use `RUST_LOG` configuration.
    #[clap(long, default_value = "false")]
    android_log: bool,
}

/// Accumulated set of observed chunks of entropy.
static SEEN: LazyLock<Mutex<HashSet<Vec<u8>>>> = LazyLock::new(Default::default);

fn get_data(idx: usize, iterations: usize, addr: PathBuf) -> Result<()> {
    info!("[{idx}]: perform {iterations} retrievals from {addr:?}");
    let start = Instant::now();
    for i in 0..iterations {
        let sock = socket(AddressFamily::Unix, SockType::Stream, SockFlag::empty(), None)
            .context(format!("[{idx}].{i}: failed to create socket"))?;
        connect(sock.as_raw_fd(), &UnixAddr::new(&addr).context("failed to create address")?)
            .context(format!("[{idx}].{i}: failed to connect socket"))?;

        // Safety: FD successfully created above
        let mut file = unsafe { std::fs::File::from_raw_fd(sock.as_raw_fd()) };
        let mut buffer = Vec::with_capacity(DATA_LEN);

        let iter_start = Instant::now();
        let size = file.read_to_end(&mut buffer).context(format!("[{idx}].{i}: failed to read"))?;
        let iter_time = iter_start.elapsed();
        let prefix = std::cmp::min(12, size);
        debug!(
            "[{idx}].{i}: retrieved {size} bytes of data in {iter_time:?}: {}...",
            hex::encode(&buffer[0..prefix])
        );

        if !buffer.is_empty() {
            // Any nonempty data that is returned should be unique.
            let mut seen = SEEN.lock().unwrap();
            if seen.contains(&buffer) {
                panic!(
                    "[{idx}.{i}]: same entropy chunk observed more than once! {}",
                    hex::encode(&buffer)
                );
            }
            seen.insert(buffer);
        }
    }
    info!("[{idx}]: performed {iterations} retrievals {:?}", start.elapsed());
    Ok(())
}

fn main() -> Result<()> {
    let opts = Options::try_parse()?;
    if opts.android_log {
        logger::init(
            logger::Config::default()
                .with_tag_on_device("prng_seeder_client")
                .with_max_level(LevelFilter::Debug),
        );
    } else {
        env_logger::init();
    }

    let handles: Vec<_> = (0..opts.threads)
        .map(|idx| {
            let socket = opts.socket.clone();
            std::thread::spawn(move || {
                if let Err(e) = get_data(idx, opts.iterations, socket) {
                    log::error!("[{idx}]: thread failed: {e:?}");
                }
            })
        })
        .collect();
    let _results: Vec<_> = handles.into_iter().map(|h| h.join()).collect();
    Ok(())
}
