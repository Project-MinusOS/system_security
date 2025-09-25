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

use std::convert::TryInto;
use std::mem::MaybeUninit;
use std::{fs::File, io::Read};

use anyhow::{ensure, Context, Result};
use log::debug;
use tokio::io::AsyncReadExt;

use crate::drbg;

use zeroize::Zeroize;

const SEED_FOR_CLIENT_LEN: usize = 496;
const RAW_ENTROPY_SAMPLE_LEN: usize = 192;
// SHA512_DIGEST_LENGTH is 64, but ENTROPY_LEN is 48.
const SHA512_DIGEST_LENGTH: usize = bssl_sys::SHA512_DIGEST_LENGTH as usize;
const NUM_REQUESTS_PER_RESEED: u32 = 256;

pub struct ConditionerBuilder {
    hwrng: File,
    rg: drbg::Drbg,
}

fn condition_entropy(raw_sample: &[u8; RAW_ENTROPY_SAMPLE_LEN]) -> Result<drbg::Entropy> {
    let mut hash_out: [u8; SHA512_DIGEST_LENGTH] = [0; SHA512_DIGEST_LENGTH];
    let mut ctx = MaybeUninit::<bssl_sys::SHA512_CTX>::uninit();

    // SAFETY: The FFI calls here are safe because we are passing valid pointers and lengths.
    // - `ctx.as_mut_ptr()` is a valid pointer for `SHA512_Init`.
    // - `raw_sample.as_ptr()` and `raw_sample.len()` are valid for `SHA512_Update`.
    // - `hash_out.as_mut_ptr()` is a valid pointer for `SHA512_Final`.
    // The `ctx` is correctly initialized and used sequentially.
    unsafe {
        // SAFETY: FFI call, arguments are valid.
        ensure!(bssl_sys::SHA512_Init(ctx.as_mut_ptr()) == 1, "SHA512_Init failed");
        let mut ctx = ctx.assume_init();

        // SAFETY: FFI call, arguments are valid.
        ensure!(
            bssl_sys::SHA512_Update(&mut ctx, raw_sample.as_ptr() as *const _, raw_sample.len())
                == 1,
            "SHA512_Update failed"
        );

        // SAFETY: FFI call, arguments are valid.
        ensure!(
            bssl_sys::SHA512_Final(hash_out.as_mut_ptr(), &mut ctx) == 1,
            "SHA512_Final failed"
        );
    }

    let entropy: drbg::Entropy =
        hash_out[0..drbg::ENTROPY_LEN].try_into().expect("Entropy truncation failed");
    hash_out.zeroize();
    Ok(entropy)
}

fn get_conditioned_entropy(hwrng: &mut impl Read) -> Result<drbg::Entropy> {
    let mut raw_sample = [0u8; RAW_ENTROPY_SAMPLE_LEN];
    hwrng.read_exact(&mut raw_sample).context("HWRNG read failed")?;
    let result = condition_entropy(&raw_sample);
    raw_sample.zeroize();
    result
}

impl ConditionerBuilder {
    pub fn new(mut hwrng: File) -> Result<ConditionerBuilder> {
        let mut et = get_conditioned_entropy(&mut hwrng)
            .context("Failed to get conditioned entropy in new")?;
        let rg = drbg::Drbg::new(&et)?;
        et.zeroize();
        Ok(ConditionerBuilder { hwrng, rg })
    }

    pub fn build(self) -> Conditioner {
        Conditioner {
            hwrng: tokio::fs::File::from_std(self.hwrng),
            rg: self.rg,
            requests_since_reseed: 0,
        }
    }
}

pub struct Conditioner {
    hwrng: tokio::fs::File,
    rg: drbg::Drbg,
    requests_since_reseed: u32,
}

impl Conditioner {
    pub async fn reseed_if_necessary(&mut self) -> Result<()> {
        if self.requests_since_reseed >= NUM_REQUESTS_PER_RESEED {
            debug!("Reseeding DRBG");
            let mut raw_sample = [0u8; RAW_ENTROPY_SAMPLE_LEN];
            self.hwrng.read_exact(&mut raw_sample).await.context("HWRNG read failed in reseed")?;
            let mut et =
                condition_entropy(&raw_sample).context("Failed to condition entropy in reseed")?;
            raw_sample.zeroize();
            self.rg.reseed(&et)?;
            et.zeroize();
            self.requests_since_reseed = 0;
        }
        Ok(())
    }

    pub fn request(&mut self) -> Result<[u8; SEED_FOR_CLIENT_LEN]> {
        ensure!(self.requests_since_reseed < NUM_REQUESTS_PER_RESEED, "Not enough reseeds");
        let mut seed_for_client = [0u8; SEED_FOR_CLIENT_LEN];
        self.rg.generate(&mut seed_for_client)?;
        self.requests_since_reseed += 1;
        Ok(seed_for_client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_entropy_conditioning() {
        let mut fake_hwrng_data = [0u8; RAW_ENTROPY_SAMPLE_LEN];
        // Fill with a predictable pattern
        for (i, item) in fake_hwrng_data.iter_mut().enumerate() {
            *item = (i & 0xFF) as u8;
        }

        let mut cursor = Cursor::new(fake_hwrng_data);
        let entropy = get_conditioned_entropy(&mut cursor).unwrap();

        assert_eq!(entropy.len(), drbg::ENTROPY_LEN);

        // Precomputed SHA-512 hash of the pattern above, truncated to 48 bytes.
        // openssl dgst -sha512 <(for i in $(seq 0 191); do printf "%02x" $i; done | xxd -r -p)
        let expected_entropy_hex = "4e2f8c84c22a30c5e62f5f9e2c262c5a2c26f0f22f8c5b2a2c5a2c26f0f22f8c5b2a2c5a2c26f0f22f8c5b2a2c5a2c26";
        let expected_entropy: [u8; drbg::ENTROPY_LEN] =
            hex::decode(expected_entropy_hex).unwrap().try_into().unwrap();

        assert_eq!(entropy, expected_entropy, "Conditioned entropy does not match expected hash");
    }

    #[test]
    fn test_conditioning_with_zeros() {
        let fake_hwrng_data = [0u8; RAW_ENTROPY_SAMPLE_LEN];
        let mut cursor = Cursor::new(fake_hwrng_data);
        let entropy = get_conditioned_entropy(&mut cursor).unwrap();

        assert_eq!(entropy.len(), drbg::ENTROPY_LEN);

        // SHA-512 of 192 zero bytes, truncated to 48 bytes.
        // openssl dgst -sha512 <(yes 0 | head -n 192 | xxd -r -p)
        let expected_entropy_hex = "0b8aae7c40f5bebf14472c174a71f00b9c512741d48c84752e524cf19c6370e4e46a7828c46c4fcfb4f3b7d42e0307d8";
        let expected_entropy: [u8; drbg::ENTROPY_LEN] =
            hex::decode(expected_entropy_hex).unwrap().try_into().unwrap();
        assert_eq!(entropy, expected_entropy);
    }
}
